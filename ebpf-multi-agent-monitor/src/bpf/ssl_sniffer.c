#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>
#include "common.h" 
#include "ssl_sniffer.skel.h"

#define SSL_RB_PIN_PATH "/sys/fs/bpf/ssl_rb"

// Uprobe 挂载去重机制
#define MAX_ATTACHED_LIBS 64
static char attached_paths[MAX_ATTACHED_LIBS][512];
static int attached_paths_count = 0;

static bool is_path_attached(const char *path) {
    for (int i = 0; i < attached_paths_count; i++) {
        if (strcmp(attached_paths[i], path) == 0) return true;
    }
    return false;
}

static void mark_path_attached(const char *path) {
    if (attached_paths_count < MAX_ATTACHED_LIBS) {
        strncpy(attached_paths[attached_paths_count++], path, 511);
    }
}

// 全局骨架指针
static struct ssl_sniffer_bpf *skel = NULL;

// 存储所有 uprobe link 以便安全清理
#define MAX_UPROBE_LINKS 2048
static struct bpf_link *uprobe_links[MAX_UPROBE_LINKS];
static int uprobe_link_count = 0;

static void store_link(struct bpf_link *link) {
    if (link && !libbpf_get_error(link) && uprobe_link_count < MAX_UPROBE_LINKS) {
        uprobe_links[uprobe_link_count++] = link;
    }
}

static void destroy_all_links(void) {
    for (int i = 0; i < uprobe_link_count; i++) {
        bpf_link__destroy(uprobe_links[i]);
    }
    uprobe_link_count = 0;
}

// 挂载探针宏
#define ATTACH_UPROBE(skel, bin, sym, prog, is_retprobe) do { \
    LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = sym, .retprobe = is_retprobe); \
    struct bpf_link *link = bpf_program__attach_uprobe_opts(skel->progs.prog, -1, bin, 0, &opts); \
    if (libbpf_get_error(link)) fprintf(stderr, "[-] Failed to attach %s to %s\n", sym, bin); \
    else { printf("[+] Attached %s to %s\n", sym, bin); store_link(link); } \
} while(0)

// 按物理地址偏移量挂载的宏
#define ATTACH_UPROBE_OFFSET(skel, bin, offset, prog, is_retprobe) do { \
    LIBBPF_OPTS(bpf_uprobe_opts, opts, .retprobe = is_retprobe); \
    struct bpf_link *link = bpf_program__attach_uprobe_opts(skel->progs.prog, -1, bin, offset, &opts); \
    if (libbpf_get_error(link)) fprintf(stderr, "[-] Failed to attach offset 0x%zx to %s\n", offset, bin); \
    else { printf("[+] Attached offset 0x%zx to %s\n", offset, bin); store_link(link); } \
} while(0)

static bool verbose = false;

struct boringssl_offsets {
	size_t ssl_write;
	size_t ssl_read;
	size_t ssl_do_handshake;
	bool found;
};

// ------------------------------------------------------------------
// 寻找偏移
// ------------------------------------------------------------------
static size_t find_pattern(const unsigned char *data, size_t data_len,
    const unsigned char *pattern, size_t pattern_len)
{
    if (pattern_len > data_len)
        return (size_t)-1;
    for (size_t i = 0; i <= data_len - pattern_len; i++) {
        if (memcmp(data + i, pattern, pattern_len) == 0)
            return i;
    }
    return (size_t)-1;
}

static struct boringssl_offsets find_boringssl_offsets(const char *binary_path) {
	struct boringssl_offsets result = { .found = false };
	int fd = -1;
	struct stat st;
	unsigned char *data = NULL;

	static const unsigned char handshake_pat[] = {
		0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
		0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
		0x28, 0x49, 0x89, 0xfc, 0x48, 0x8b, 0x47, 0x30
	};
	static const unsigned char read_pat[] = {
		0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
		0x53, 0x50, 0x48, 0x83, 0xbf, 0x98, 0x00, 0x00,
		0x00, 0x00, 0x74
	};
	static const unsigned char write_pat[] = {
		0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
		0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
		0x18, 0x41, 0x89, 0xd7, 0x49, 0x89, 0xf6, 0x48,
		0x89, 0xfb
	};

	static const size_t READ_HANDSHAKE_DELTA = 0x6F0;
	static const size_t WRITE_READ_DELTA = 0xCA0;

	fd = open(binary_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", binary_path, strerror(errno));
		return result;
	}

	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "Failed to stat %s: %s\n", binary_path, strerror(errno));
		close(fd);
		return result;
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		fprintf(stderr, "Failed to mmap %s: %s\n", binary_path, strerror(errno));
		close(fd);
		return result;
	}

	size_t read_off = find_pattern(data, st.st_size, read_pat, sizeof(read_pat));
	if (read_off == (size_t)-1) {
		if (verbose) fprintf(stderr, "BoringSSL: SSL_read pattern not found\n");
		goto out;
	}

	if (read_off >= READ_HANDSHAKE_DELTA) {
		size_t expected_hs = read_off - READ_HANDSHAKE_DELTA;
		if (memcmp(data + expected_hs, handshake_pat, sizeof(handshake_pat)) == 0) {
			result.ssl_do_handshake = expected_hs;
		}
	}
	if (result.ssl_do_handshake == 0) {
		size_t hs_off = find_pattern(data, st.st_size, handshake_pat, sizeof(handshake_pat));
		if (hs_off == (size_t)-1) {
			if (verbose) fprintf(stderr, "BoringSSL: SSL_do_handshake pattern not found\n");
			goto out;
		}
		result.ssl_do_handshake = hs_off;
	}

	result.ssl_read = read_off;

	size_t expected_wr = read_off + WRITE_READ_DELTA;
	if (expected_wr + sizeof(write_pat) <= (size_t)st.st_size &&
		memcmp(data + expected_wr, write_pat, sizeof(write_pat)) == 0) {
		result.ssl_write = expected_wr;
	} else {
		size_t search_start = read_off;
		size_t search_end = read_off + 0x10000;
		if (search_end > (size_t)st.st_size) search_end = st.st_size;
		size_t wr_off = find_pattern(data + search_start, search_end - search_start, write_pat, sizeof(write_pat));
		if (wr_off == (size_t)-1) {
			if (verbose) fprintf(stderr, "BoringSSL: SSL_write pattern not found near SSL_read\n");
			goto out;
		}
		result.ssl_write = search_start + wr_off;
	}

	result.found = true;
	if (verbose) {
		fprintf(stderr, "BoringSSL detected in %s:\n", binary_path);
		fprintf(stderr, "  SSL_do_handshake offset: 0x%lx\n", result.ssl_do_handshake);
		fprintf(stderr, "  SSL_read offset:         0x%lx\n", result.ssl_read);
		fprintf(stderr, "  SSL_write offset:        0x%lx\n", result.ssl_write);
	}

out:
	munmap(data, st.st_size);
	close(fd);
	return result;
}

// ------------------------------------------------------------------
// 动态扫描目标进程环境，路由挂载策略
// ------------------------------------------------------------------
void attach_probes_dynamically(struct ssl_sniffer_bpf *skel, int *pids, int count) {
    // 遍历所有捕获到的智能体 PID
    for (int i = 0; i < count; i++) {
        int target_pid = pids[i];
        char maps_path[256];
        char exe_path[256];
        char line[512];
        int openssl_found = 0;

        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", target_pid);

        char real_exe[512];
        const char *target_bin_path = real_exe; 

        ssize_t len = readlink(exe_path, real_exe, sizeof(real_exe)-1);
        if (len != -1) {
            real_exe[len] = '\0';
            if (strstr(real_exe, " (deleted)") != NULL) {
                target_bin_path = exe_path; 
            }
        } else {
            target_bin_path = exe_path;
        }

        FILE *f = fopen(maps_path, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "libssl.so")) {
                    char *lib_path = strchr(line, '/');
                    if (lib_path) {
                        lib_path[strcspn(lib_path, "\n")] = 0;
                        openssl_found = 1;

                        // 检查这个 libssl.so 是否已经被其他 Agent 挂载过了
                        if (!is_path_attached(lib_path)) {
                            printf("[*] [PID:%d] 发现新的 OpenSSL 动态库: %s\n", target_pid, lib_path);
                            // SSL_write + SSL_read 标准函数
                            ATTACH_UPROBE(skel, lib_path, "SSL_write", probe_SSL_rw_enter, false);
                            ATTACH_UPROBE(skel, lib_path, "SSL_write", probe_SSL_write_exit, true);
                            ATTACH_UPROBE(skel, lib_path, "SSL_read", probe_SSL_rw_enter, false);
                            ATTACH_UPROBE(skel, lib_path, "SSL_read", probe_SSL_read_exit, true);

                            // SSL_write_ex + SSL_read_ex 现代扩展函数
                            ATTACH_UPROBE(skel, lib_path, "SSL_write_ex", probe_SSL_write_ex_enter, false);
                            ATTACH_UPROBE(skel, lib_path, "SSL_write_ex", probe_SSL_write_ex_exit, true);
                            ATTACH_UPROBE(skel, lib_path, "SSL_read_ex", probe_SSL_read_ex_enter, false);
                            ATTACH_UPROBE(skel, lib_path, "SSL_read_ex", probe_SSL_read_ex_exit, true);

                            // SSL_do_handshake
                            ATTACH_UPROBE(skel, lib_path, "SSL_do_handshake", probe_SSL_do_handshake_enter, false);
                            ATTACH_UPROBE(skel, lib_path, "SSL_do_handshake", probe_SSL_do_handshake_exit, true);
                            mark_path_attached(lib_path); // 记录已挂载
                        } else {
                            printf("[-] [PID:%d] 复用已挂载的 OpenSSL: %s\n", target_pid, lib_path);
                        }
                        break;
                    }
                }
            }
            fclose(f);
        }

        if (openssl_found) continue;

        // 检查目标可执行文件本身是否已经挂载过探针
        if (!is_path_attached(target_bin_path)) {
            if (strstr(target_bin_path, "agent") || strstr(target_bin_path, "gateway") || strstr(target_bin_path, "openclaw")) {
                printf("[*] [PID:%d] 尝试按 Go 语言符号进行挂载: %s\n", target_pid, target_bin_path);
                ATTACH_UPROBE(skel, target_bin_path, "crypto/tls.(*Conn).Write", go_tls_write_enter, false);
                ATTACH_UPROBE(skel, target_bin_path, "crypto/tls.(*Conn).Read", go_tls_read_enter, false);
            } else {
                printf("[*] [PID:%d] 尝试通过机器码特征提取 BoringSSL 偏移量...\n", target_pid);
                struct boringssl_offsets offsets = find_boringssl_offsets(target_bin_path); 
                
                if (offsets.found) {
                    printf("[+] 特征码匹配成功，使用物理偏移量挂载探针...\n");
                    ATTACH_UPROBE_OFFSET(skel, target_bin_path, offsets.ssl_write, probe_SSL_rw_enter, false);
                    ATTACH_UPROBE_OFFSET(skel, target_bin_path, offsets.ssl_write, probe_SSL_write_exit, true);
                    ATTACH_UPROBE_OFFSET(skel, target_bin_path, offsets.ssl_read, probe_SSL_rw_enter, false);
                    ATTACH_UPROBE_OFFSET(skel, target_bin_path, offsets.ssl_read, probe_SSL_read_exit, true);
                } else {
                    printf("[-] 特征码匹配失败。尝试按 Node 默认符号表挂载...\n");
                    ATTACH_UPROBE(skel, target_bin_path, "SSL_write", probe_SSL_rw_enter, false);
                    ATTACH_UPROBE(skel, target_bin_path, "SSL_write", probe_SSL_write_exit, true);
                    ATTACH_UPROBE(skel, target_bin_path, "SSL_read", probe_SSL_rw_enter, false);
                    ATTACH_UPROBE(skel, target_bin_path, "SSL_read", probe_SSL_read_exit, true);
                }
            }
            mark_path_attached(target_bin_path); // 记录已挂载
        } else {
            printf("[-] [PID:%d] 复用已挂载的静态环境: %s\n", target_pid, target_bin_path);
        }
    }
}
// ==================================================================
// 接口
// ==================================================================

/**
 * 初始化并挂载 SSL 探针 (接收多目标数组)
 * @param target_pids 目标进程 PID 数组
 * @param count 智能体数量
 * @return 0 成功, -1 失败
 */
int setup_ssl_sniffer(int *target_pids, int count) {
    if (count <= 0) {
        fprintf(stderr, "[-] Invalid Target PIDs count\n");
        return -1;
    }

    printf("[SSL_SNIFFER] 启动并发动态挂载引擎，目标数: %d...\n", count);
    attached_paths_count = 0; // 清空挂载记录

    skel = ssl_sniffer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to load BPF skeleton\n");
        return -1;
    }

    // 调用支持数组和去重的挂载函数
    attach_probes_dynamically(skel, target_pids, count);

    bpf_map__unpin(skel->maps.rb, SSL_RB_PIN_PATH);
    if (bpf_map__pin(skel->maps.rb, SSL_RB_PIN_PATH) != 0) {
        fprintf(stderr, "[-] Failed to pin SSL ring buffer to %s\n", SSL_RB_PIN_PATH);
        ssl_sniffer_bpf__destroy(skel);
        skel = NULL;
        return -1;
    }

    printf("[+] SSL Sniffer probes attached and map pinned successfully.\n");
    return 0;
}

/**
 *  动态增量挂载新启动的智能体
 */
int add_new_agents_ssl(int *target_pids, int count) {
    if (!skel) {
        fprintf(stderr, "[-] add_new_agents_ssl: Skeleton not loaded!\n");
        return -1;
    }

    attach_probes_dynamically(skel, target_pids, count);
    
    return 0;
}

int get_agent_info_map_fd(void) {
    if (!skel) return -1;
    return bpf_map__fd(skel->maps.agent_info_map);
}

/**
 * 卸载清理 SSL 探针
 */
void teardown_ssl_sniffer(void) {
    if (skel) {
        destroy_all_links();
        bpf_map__unpin(skel->maps.rb, SSL_RB_PIN_PATH);
        ssl_sniffer_bpf__destroy(skel);
        skel = NULL;
        printf("[+] SSL Sniffer detached and cleaned up.\n");
    }
}