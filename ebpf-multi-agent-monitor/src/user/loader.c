#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "libbpf.h"
#include "bpf.h"
#include "sys_behavior.skel.h"
#include "ssl_sniffer.skel.h"

#define TRACE_PIPE_PATH_DEBUGFS "/sys/kernel/debug/tracing/trace_pipe"
#define TRACE_PIPE_PATH_TRACEFS "/sys/kernel/tracing/trace_pipe"

// 定义 BPF Map 钉固的路径
#define SYS_RB_PIN_PATH "/sys/fs/bpf/sys_rb"
#define SSL_RB_PIN_PATH "/sys/fs/bpf/ssl_rb"

static volatile int running = 1;

static int raise_memlock_limit(void)
{
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &lim) == 0) {
        return 0;
    }

    return -errno;
}

static void relax_pin_permissions(const char *path)
{
    const char *uid_str = getenv("SUDO_UID");
    const char *gid_str = getenv("SUDO_GID");
    uid_t uid;
    gid_t gid;

    if (!uid_str || !gid_str || !path) {
        return;
    }

    uid = (uid_t)strtoul(uid_str, NULL, 10);
    gid = (gid_t)strtoul(gid_str, NULL, 10);

    if (chown(path, uid, gid) != 0) {
        fprintf(stderr, "[LOADER] Warning: failed to chown %s: %s\n", path, strerror(errno));
        return;
    }

    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        fprintf(stderr, "[LOADER] Warning: failed to chmod %s: %s\n", path, strerror(errno));
        return;
    }
}

static FILE *open_trace_pipe(void)
{
    FILE *trace_file = fopen(TRACE_PIPE_PATH_DEBUGFS, "r");
    if (trace_file) {
        return trace_file;
    }

    return fopen(TRACE_PIPE_PATH_TRACEFS, "r");
}

void signal_handler(int sig)
{
    (void)sig;
    printf("\n[LOADER] Stopping trace logger and cleaning up BPF...\n");
    running = 0;
}

static void destroy_skeletons(struct sys_behavior_bpf_bpf *sys_skel,
                              struct ssl_sniffer_bpf_bpf *ssl_skel)
{
    if (sys_skel) {
        sys_behavior_bpf_bpf__destroy(sys_skel);
    }
    if (ssl_skel) {
        ssl_sniffer_bpf_bpf__destroy(ssl_skel);
    }
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int err = 0;
    struct sys_behavior_bpf_bpf *sys_skel = NULL;
    struct ssl_sniffer_bpf_bpf *ssl_skel = NULL;

    printf("[LOADER] eBPF Loader starting... (Handling BPF attach and Map pinning)\n");

    err = raise_memlock_limit();
    if (err != 0) {
        fprintf(stderr,
                "[LOADER] Failed to raise RLIMIT_MEMLOCK (%d). "
                "Run as root or with CAP_BPF/CAP_SYS_RESOURCE.\n",
                err);
    }

    // 1. 加载并挂载系统行为 BPF 骨架
    sys_skel = sys_behavior_bpf_bpf__open_and_load();
    if (!sys_skel) {
        fprintf(stderr, "[LOADER] Failed to load sys_behavior\n");
        return 1;
    }
    err = sys_behavior_bpf_bpf__attach(sys_skel);
    if (err != 0) {
        fprintf(stderr, "[LOADER] Failed to attach sys_behavior: %d\n", err);
        destroy_skeletons(sys_skel, NULL);
        return 1;
    }

    // 2. 加载并挂载 SSL 嗅探 BPF 骨架
    ssl_skel = ssl_sniffer_bpf_bpf__open_and_load();
    if (!ssl_skel) {
        fprintf(stderr, "[LOADER] Failed to load ssl_sniffer\n");
        destroy_skeletons(sys_skel, NULL);
        return 1;
    }
    err = ssl_sniffer_bpf_bpf__attach(ssl_skel);
    if (err != 0) {
        fprintf(stderr, "[LOADER] Failed to attach ssl_sniffer: %d\n", err);
        destroy_skeletons(sys_skel, ssl_skel);
        return 1;
    }

    // 3. 将 RingBuffer Map 钉固 (Pin) 到文件系统，供 ringbuf_handler 读取
    // 钉固前先尝试解绑，防止上次异常退出导致残留
    bpf_map__unpin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
    bpf_map__unpin(ssl_skel->maps.ssl_rb, SSL_RB_PIN_PATH);

    if (bpf_map__pin(sys_skel->maps.rb, SYS_RB_PIN_PATH) != 0 || 
        bpf_map__pin(ssl_skel->maps.ssl_rb, SSL_RB_PIN_PATH) != 0) {
        fprintf(stderr, "[LOADER] Failed to pin maps to /sys/fs/bpf/\n");
        destroy_skeletons(sys_skel, ssl_skel);
        return 1;
    }

    relax_pin_permissions(SYS_RB_PIN_PATH);
    relax_pin_permissions(SSL_RB_PIN_PATH);
    printf("[LOADER] BPF programs attached and Maps pinned successfully.\n");
    
    // 4. 原有的 trace_pipe 监听逻辑
    FILE *trace_file = open_trace_pipe();
    if (!trace_file) {
        fprintf(stderr,
                "[LOADER] Warning: trace_pipe is unavailable; continuing without BPF trace logs.\n");
    }

    // 使用 sigaction 替代老式 signal，避免 getline 被自动重启
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // 核心：设为 0，坚决不用 SA_RESTART

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to set SIGINT handler");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Failed to set SIGTERM handler");
    }

    char *line = NULL;
    size_t len = 0;

    while (running) {
        if (trace_file && getline(&line, &len, trace_file) != -1) {
            // 过滤只打印带 [BPF] 标签的日志
            if (strstr(line, "[BPF]") != NULL) {
                printf("%s", line);
            }
        } else {
            usleep(100000); 
        }
    }

    // 5. 退出时清理资源和钉固文件
    if (line) free(line);
    if (trace_file) fclose(trace_file);

    bpf_map__unpin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
    bpf_map__unpin(ssl_skel->maps.ssl_rb, SSL_RB_PIN_PATH);
    destroy_skeletons(sys_skel, ssl_skel);
    printf("[LOADER] Exited cleanly.\n");

    return 0;
}
