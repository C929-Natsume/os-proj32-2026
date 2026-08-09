#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include "common.h"
#include "filter.h"

// 数据传输管道
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 追踪
// 解决 os.system 产生 sh 和 cat 等子进程导致名字改变、被白名单误杀的问题
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // 进程 PID
    __type(value, struct process_context);  // 是否受监控标志
} monitored_pids SEC(".maps");

// 系统资源占用
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct res_key);
    __type(value, struct res_val);
} resource_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} sched_start SEC(".maps");

// 监听端口 → 进程 PID 映射表，用于检测智能体间通信
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct tcp_listen_key);
    __type(value, __u32);
} listen_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} raw_rb SEC(".maps");

// fd → 对端智能体身份映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct fd_peer_info);
} fd_peer_map SEC(".maps");

// enter→exit 参数传递（recvfrom/read：enter 存 buf 指针，exit 读已填充的数据）
struct pending_arg {
    __u64 buf_ptr;
    __u32 fd;
    __u32 len;
    __u32 peer;
    __u32 source;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // tid
    __type(value, struct pending_arg);
} pending_recv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // tid
    __type(value, struct pending_arg);
} pending_read SEC(".maps");

// enter→exit 参数传递（recvmsg：enter 存 msg 指针，exit 读已填充的 iovec）
struct pending_msg_arg {
    __u64 msg_ptr;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // tid
    __type(value, struct pending_msg_arg);
} pending_msg SEC(".maps");

// 行为识别开关 (0=关闭, 1=开启)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} behavioral_discovery_enabled SEC(".maps");

// 未知进程候选评分 (行为识别引擎)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct candidate_score);
} unknown_candidate_map SEC(".maps");

// Ring buffer 丢弃计数 — 消除静默数据丢失
enum drop_reason {
    DROP_SYS_EVENT,
    DROP_CONNECT_EVENT,
    DROP_FORK_EVENT,
    DROP_RAW_EVENT,
    DROP_MSGHDR_EVENT,
    DROP_REASON_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_REASON_MAX);
    __type(key, __u32);
    __type(value, __u64);
} drop_counters SEC(".maps");

static __always_inline void inc_drop(enum drop_reason reason) {
    __u32 key = reason;
    __u64 *cnt = bpf_map_lookup_elem(&drop_counters, &key);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

// 子智能体识别
#define CANDIDATE_SUB_AGENT 2
#define CONFIRMED_SUB_AGENT 1
#define NORMAL_TOOL         0

static __always_inline bool is_known_tool_comm(void) {
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'c' && comm[1] == 'u' && comm[2] == 'r' && comm[3] == 'l') return true;
    if (comm[0] == 'w' && comm[1] == 'g' && comm[2] == 'e' && comm[3] == 't') return true;
    if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h') return true;
    if (comm[0] == 'g' && comm[1] == 'i' && comm[2] == 't') return true;
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') return true;
    if (comm[0] == 's' && comm[1] == 'h') return true;
    return false;
}

static __always_inline bool promote_to_sub_agent(__u32 pid) {
    struct process_context *child_ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!child_ctx) return false;
    if (child_ctx->is_sub_agent != CANDIDATE_SUB_AGENT) return false;
    // 已知 shell 工具不升格
    if (is_known_tool_comm()) return false;

    child_ctx->is_sub_agent = CONFIRMED_SUB_AGENT;
    child_ctx->agent_id = AGENT_ID_AUTO_DETECT(pid);
    child_ctx->depth = 1;
    return true;
}

static __always_inline bool is_behavioral_discovery_enabled(void) {
    __u32 key = 0;
    __u8 *val = bpf_map_lookup_elem(&behavioral_discovery_enabled, &key);
    return val && (*val == 1);
}

static __always_inline void update_candidate_score(__u32 pid, __u8 flag_type) {
    if (!is_behavioral_discovery_enabled())
        return;

    struct candidate_score *score = bpf_map_lookup_elem(&unknown_candidate_map, &pid);
    __u64 now = bpf_ktime_get_ns();

    if (!score) {
        struct candidate_score new_score = {0};
        new_score.first_seen_ns = now;
        bpf_map_update_elem(&unknown_candidate_map, &pid, &new_score, BPF_ANY);
        score = bpf_map_lookup_elem(&unknown_candidate_map, &pid);
        if (!score) return;
    }

    if (score->flags & 0x80)
        return;

    if ((now - score->first_seen_ns) > DISCOVERY_TIME_WINDOW_NS) {
        score->sys_event_count = 0;
        score->raw_data_count = 0;
        score->first_seen_ns = now;
        score->flags = 0;
    }

    if (flag_type == 0) {
        __sync_fetch_and_add(&score->sys_event_count, 1);
        score->flags |= 1;
    } else {
        __sync_fetch_and_add(&score->raw_data_count, 1);
        score->flags |= 2;
    }
}

static __always_inline void check_and_promote_unknown(__u32 pid) {
    if (!is_behavioral_discovery_enabled())
        return;

    struct candidate_score *score = bpf_map_lookup_elem(&unknown_candidate_map, &pid);
    if (!score) return;
    if (score->flags & 0x80) return;

    __u64 now = bpf_ktime_get_ns();
    if ((now - score->first_seen_ns) > DISCOVERY_TIME_WINDOW_NS) return;
    if (score->sys_event_count < DISCOVERY_SYS_EVENT_THRESHOLD) return;
    if (score->raw_data_count < DISCOVERY_LLM_MATCH_THRESHOLD) return;

    struct process_context new_ctx = {0};
    new_ctx.agent_id = AGENT_ID_BEHAVIORAL(pid);
    new_ctx.is_sub_agent = CONFIRMED_SUB_AGENT;
    new_ctx.parent_pid = 0;
    new_ctx.depth = 0;
    char default_name[] = "Behavioral-Agent";
    __builtin_memcpy(new_ctx.agent_name, default_name, sizeof(default_name));

    bpf_map_update_elem(&monitored_pids, &pid, &new_ctx, BPF_ANY);
    score->flags |= 0x80;

    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) return;
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_AGENT_DISCOVERY;
    event->pid = pid;
    event->timestamp = now;
    event->agent_id = new_ctx.agent_id;
    __builtin_memcpy(event->agent_name, new_ctx.agent_name, MAX_AGENT_NAME_LEN);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    bpf_map_delete_elem(&unknown_candidate_map, &pid);
}

static __always_inline bool is_ai_api_port(__u16 dport_host) {
    return (dport_host == 443 || dport_host == 8000 ||
            dport_host == 11434 || dport_host == 8080 ||
            dport_host == 9090);
}

#define FP_SCAN_LEN 32

static __always_inline bool has_agent_protocol_fingerprint(const __u8 *buf, __u32 len) {
    if (!buf || len < 16) return false;

    #pragma unroll
    for (int i = 0; i < FP_SCAN_LEN - 8; i++) {
        if ((__u32)(i + 9) <= len &&
            buf[i] == '{' && buf[i+1] == '"' &&
            buf[i+2] == 'j' && buf[i+3] == 's' &&
            buf[i+4] == 'o' && buf[i+5] == 'n' &&
            buf[i+6] == 'r' && buf[i+7] == 'p' &&
            buf[i+8] == 'c')
            return true;
    }

    #pragma unroll
    for (int i = 0; i < FP_SCAN_LEN - 6; i++) {
        if ((__u32)(i + 7) <= len &&
            buf[i] == 'a' && buf[i+1] == 'g' &&
            buf[i+2] == 'e' && buf[i+3] == 'n' &&
            buf[i+4] == 't' && buf[i+5] == '-' &&
            buf[i+6] == 'c')
            return true;
    }

    return false;
}

// 解析 connect 目标是否为另一个受监控的智能体
static __always_inline int resolve_listen_peer(__u16 family, __u32 saddr, __u16 sport,
                                                __u32 *peer_agent_id, __u32 *peer_pid,
                                                char *peer_name) {
    if (family != 2) return 0;

    struct tcp_listen_key key = {0};
    key.saddr = saddr;
    key.sport = sport;
    key.pad = 0;

    __u32 *listen_pid = bpf_map_lookup_elem(&listen_map, &key);
    if (!listen_pid) {
        key.saddr = 0;
        listen_pid = bpf_map_lookup_elem(&listen_map, &key);
    }
    if (!listen_pid || *listen_pid == 0) return 0;

    struct process_context *peer_ctx = bpf_map_lookup_elem(&monitored_pids, listen_pid);
    if (!peer_ctx) return 0;

    *peer_pid = *listen_pid;
    *peer_agent_id = peer_ctx->agent_id;
    __builtin_memcpy(peer_name, peer_ctx->agent_name, MAX_AGENT_NAME_LEN);
    return 1;
}

static __always_inline void submit_sys_event(__u32 event_type, __u64 pid_tgid, const char *filename) {
    __u32 pid = pid_tgid >> 32;
    
    // 查找该进程所属的智能体上下文
    struct process_context *ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!ctx) {
        if (try_auto_register(&monitored_pids)) {
            ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
            if (!ctx) return;
        } else {
            if (event_type == EVENT_EXECVE || event_type == EVENT_OPEN)
                update_candidate_score(pid, 0);
            return;
        }
    }

    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) { inc_drop(DROP_SYS_EVENT); return; }

    event->event_type = event_type;
    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->child_pid = 0; 

    // 将查到的身份信息注入到传给用户态的事件中
    event->agent_id = ctx->agent_id;
    __builtin_memcpy(event->agent_name, ctx->agent_name, MAX_AGENT_NAME_LEN);
    event->parent_agent_id = ctx->parent_agent_id;
    __builtin_memcpy(event->parent_agent_name, ctx->parent_agent_name, MAX_AGENT_NAME_LEN);
    event->peer_agent_id = 0;
    event->peer_pid = 0;
    event->peer_agent_name[0] = '\0';

    if (filename) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    } else {
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
}

// IP地址
static __always_inline void format_ipv4_str(__be32 addr, char *out) {
    __u32 a = addr;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        __u8 b = (a >> (i * 8)) & 0xFF;
        if (b >= 100) {
            *out++ = '0' + (b / 100);
            *out++ = '0' + ((b / 10) % 10);
            *out++ = '0' + (b % 10);
        } else if (b >= 10) {
            *out++ = '0' + (b / 10);
            *out++ = '0' + (b % 10);
        } else {
            *out++ = '0' + b;
        }
        if (i < 3)
            *out++ = '.';
    }
    *out = '\0';
}

// 从 sockaddr 中提取目标 IP 与端口
static __always_inline void submit_connect_event(__u64 pid_tgid,
                                                  struct sockaddr *uservaddr,
                                                  int addrlen) {
    __u32 pid = pid_tgid >> 32;

    struct process_context *ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!ctx) {
        if (try_auto_register(&monitored_pids)) {
            ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
            if (!ctx)
                return;
        } else {
            update_candidate_score(pid, 0);
            return;
        }
    }

    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) { inc_drop(DROP_CONNECT_EVENT); return; }

    event->event_type = EVENT_CONNECT;
    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->child_pid = 0;
    event->filename[0] = '\0';

    event->agent_id = ctx->agent_id;
    __builtin_memcpy(event->agent_name, ctx->agent_name, MAX_AGENT_NAME_LEN);
    event->parent_agent_id = ctx->parent_agent_id;
    __builtin_memcpy(event->parent_agent_name, ctx->parent_agent_name, MAX_AGENT_NAME_LEN);

    event->peer_agent_id = 0;
    event->peer_pid = 0;
    event->peer_agent_name[0] = '\0';

    event->connect.family = 0;
    event->connect.dport = 0;
    event->connect.dip[0] = '\0';

    // 参数合法性校验
    if (!uservaddr || addrlen <= 0 || addrlen > 128)
        goto submit;

    // 读取地址族
    unsigned short family;
    if (bpf_probe_read_user(&family, sizeof(family),
                            &uservaddr->sa_family) != 0)
        goto submit;

    event->connect.family = family;

    // 提取 IP 与端口
    if (family == 2) { // AF_INET (IPv4)
        struct sockaddr_in sin = {0};
        if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) == 0) {
            event->connect.dport = bpf_ntohs(sin.sin_port);
            format_ipv4_str(sin.sin_addr.s_addr, event->connect.dip);

            // 检测 connect 目标是否为另一个受监控的智能体
            __u32 peer_aid = 0, peer_pid_val = 0;
            char peer_name[MAX_AGENT_NAME_LEN] = {0};
            if (resolve_listen_peer(family, sin.sin_addr.s_addr, sin.sin_port,
                                    &peer_aid, &peer_pid_val, peer_name)) {
                event->peer_agent_id = peer_aid;
                event->peer_pid = peer_pid_val;
                __builtin_memcpy(event->peer_agent_name, peer_name, MAX_AGENT_NAME_LEN);
                // 对端是另一个智能体时, 将事件类型提升为 AGENT_COMM
                if (peer_aid != ctx->agent_id) {
                    event->event_type = EVENT_AGENT_COMM;
                }
            }
        }
    } else if (family == 10) { // AF_INET6 (IPv6)
        struct sockaddr_in6 sin6 = {0};
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr) == 0) {
            event->connect.dport = bpf_ntohs(sin6.sin6_port);
            __u8 *raw = (__u8 *)&sin6.sin6_addr;
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                __u8 hi = (raw[i] >> 4) & 0xF;
                __u8 lo = raw[i] & 0xF;
                int pos = i * 2;
                event->connect.dip[pos] =
                    hi < 10 ? '0' + hi : 'a' + (hi - 10);
                event->connect.dip[pos + 1] =
                    lo < 10 ? '0' + lo : 'a' + (lo - 10);
            }
            event->connect.dip[32] = '\0';
        }
    }

    // 子智能体候选识别
    if (ctx->is_sub_agent == CANDIDATE_SUB_AGENT && is_ai_api_port(event->connect.dport)) {
        if (promote_to_sub_agent(pid)) {
            event->agent_id = AGENT_ID_AUTO_DETECT(pid);
        }
    }

submit:
    bpf_ringbuf_submit(event, 0);
}

//  命令执行监控
SEC("ksyscall/execve")
int BPF_KSYSCALL(sys_execve, const char *filename, const char *const *argv, const char *const *envp) {
    submit_sys_event(EVENT_EXECVE, bpf_get_current_pid_tgid(), filename);
    return 0;
}

// 文件打开监控
SEC("ksyscall/openat")
int BPF_KSYSCALL(sys_openat, int dfd, const char *filename, int flags, umode_t mode) {
    submit_sys_event(EVENT_OPEN, bpf_get_current_pid_tgid(), filename);
    return 0;
}

SEC("ksyscall/openat2")
int BPF_KSYSCALL(sys_openat2, int dfd, const char *filename, struct open_how *how, size_t usize) {
    submit_sys_event(EVENT_OPEN, bpf_get_current_pid_tgid(), filename);
    return 0;
}

SEC("ksyscall/open")
int BPF_KSYSCALL(sys_open, const char *filename, int flags, umode_t mode) {
    submit_sys_event(EVENT_OPEN, bpf_get_current_pid_tgid(), filename);
    return 0;
}

// 文件删除监控
SEC("ksyscall/unlinkat")
int BPF_KSYSCALL(sys_unlinkat, int dfd, const char *pathname, int flag) {
    submit_sys_event(EVENT_UNLINK, bpf_get_current_pid_tgid(), pathname);
    return 0;
}

SEC("ksyscall/unlink")
int BPF_KSYSCALL(sys_unlink, const char *pathname) {
    submit_sys_event(EVENT_UNLINK, bpf_get_current_pid_tgid(), pathname);
    return 0;
}

// 底层网络连接监控
SEC("ksyscall/connect")
int BPF_KSYSCALL(sys_connect, int fd, struct sockaddr *uservaddr, int addrlen) {
    submit_connect_event(bpf_get_current_pid_tgid(), uservaddr, addrlen);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_context *pctx_conn = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx_conn) return 0;

    if (!uservaddr || addrlen <= 0 || addrlen > 128) return 0;

    unsigned short family;
    if (bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family) != 0)
        return 0;

    if (family == 2) {
        struct sockaddr_in sin = {0};
        if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) == 0) {
            __u32 peer_aid = 0, peer_pid_val = 0;
            char peer_name[MAX_AGENT_NAME_LEN] = {0};
            if (resolve_listen_peer(family, sin.sin_addr.s_addr, sin.sin_port,
                                    &peer_aid, &peer_pid_val, peer_name)) {
                struct fd_peer_info peer_info = {0};
                peer_info.peer_pid = peer_pid_val;
                peer_info.peer_agent_id = peer_aid;
                __builtin_memcpy(peer_info.peer_agent_name, peer_name, MAX_AGENT_NAME_LEN);
                bpf_map_update_elem(&fd_peer_map, &fd, &peer_info, BPF_ANY);
            }
        }
    }

    return 0;
}

// 将 agent 的监听端口记录到 listen_map
SEC("ksyscall/bind")
int BPF_KSYSCALL(sys_bind, int fd, struct sockaddr *umyaddr, int addrlen) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx) return 0;

    unsigned short family;
    if (bpf_probe_read_user(&family, sizeof(family), &umyaddr->sa_family) != 0)
        return 0;

    if (family == 2) {
        struct sockaddr_in sin = {0};
        if (bpf_probe_read_user(&sin, sizeof(sin), umyaddr) == 0) {
            struct tcp_listen_key key = {0};
            key.saddr = sin.sin_addr.s_addr;
            key.sport = sin.sin_port;
            key.pad = 0;
            bpf_map_update_elem(&listen_map, &key, &pid, BPF_ANY);
        }
    }

    // 记录 listening fd 归属 agent
    struct fd_peer_info self_info = {0};
    self_info.peer_pid = pid;
    self_info.peer_agent_id = pctx->agent_id;
    __builtin_memcpy(self_info.peer_agent_name, pctx->agent_name, MAX_AGENT_NAME_LEN);
    bpf_map_update_elem(&fd_peer_map, &fd, &self_info, BPF_ANY);

    return 0;
}

SEC("ksyscall/close")
int BPF_KSYSCALL(sys_close_tcp, int fd) {
    bpf_map_delete_elem(&fd_peer_map, &fd);
    return 0;
}

// 文件权限修改监控
SEC("ksyscall/fchmodat")
int BPF_KSYSCALL(sys_fchmodat, int dfd, const char *filename, umode_t mode) {
    submit_sys_event(EVENT_CHMOD, bpf_get_current_pid_tgid(), filename);
    return 0;
}

// 进程树监控
SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid = pid_tgid >> 32;

    struct process_context *parent_ctx = bpf_map_lookup_elem(&monitored_pids, &parent_pid);
    if (!parent_ctx) return 0;

    __u32 child_pid = ctx->child_pid;

    // 清理可能存在的旧 sched_start 记录，防止 PID 重用导致 CPU 计算错误
    bpf_map_delete_elem(&sched_start, &child_pid);

    struct process_context child_ctx = {0};
    child_ctx.parent_pid = parent_pid;
    child_ctx.depth = parent_ctx->depth + 1;

    if (parent_ctx->is_sub_agent >= CONFIRMED_SUB_AGENT) {
        // 父进程是智能体 → 子进程标记为候选子智能体
        child_ctx.is_sub_agent = CANDIDATE_SUB_AGENT;
        child_ctx.agent_id = parent_ctx->agent_id;  // 暂继承，待确认后分配新 ID
        child_ctx.parent_agent_id = parent_ctx->agent_id;
        __builtin_memcpy(child_ctx.parent_agent_name, parent_ctx->agent_name, MAX_AGENT_NAME_LEN);
    } else {
        // 普通进程的子进程
        child_ctx.is_sub_agent = NORMAL_TOOL;
        child_ctx.agent_id = parent_ctx->agent_id;
        child_ctx.parent_agent_id = parent_ctx->parent_agent_id;
        __builtin_memcpy(child_ctx.parent_agent_name, parent_ctx->parent_agent_name, MAX_AGENT_NAME_LEN);
    }
    __builtin_memcpy(child_ctx.agent_name, parent_ctx->agent_name, MAX_AGENT_NAME_LEN);

    bpf_map_update_elem(&monitored_pids, &child_pid, &child_ctx, BPF_ANY);

    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) { inc_drop(DROP_FORK_EVENT); return 0; }

    event->event_type = EVENT_FORK;
    event->pid = parent_pid; 
    event->child_pid = child_pid;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    
    event->agent_id = parent_ctx->agent_id;
    __builtin_memcpy(event->agent_name, parent_ctx->agent_name, MAX_AGENT_NAME_LEN);
    event->parent_agent_id = parent_ctx->parent_agent_id;
    __builtin_memcpy(event->parent_agent_name, parent_ctx->parent_agent_name, MAX_AGENT_NAME_LEN);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 资源占用监控
SEC("tp_btf/sched_switch")
int BPF_PROG(trace_sched_switch_btf, bool preempt, struct task_struct *prev, struct task_struct *next) {
    __u32 prev_pid = BPF_CORE_READ(prev, pid);
    __u32 next_pid = BPF_CORE_READ(next, pid);
    __u64 now = bpf_ktime_get_ns();

    __u64 *start_ts = bpf_map_lookup_elem(&sched_start, &prev_pid);
    if (start_ts) {
        __u64 delta = now - *start_ts;
        bpf_map_delete_elem(&sched_start, &prev_pid);

        struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &prev_pid);
        if (pctx) {
            struct res_key k = {RES_LEVEL_PID, prev_pid}; 
            struct res_val *v = bpf_map_lookup_elem(&resource_map, &k);
            
            if (v) {
                __sync_fetch_and_add(&v->cpu_time_ns, delta); 
            } else {
                struct res_val new_v = {0};
                new_v.cpu_time_ns = delta;
                new_v.mem_rss_bytes = 0;
                new_v.agent_id = pctx->agent_id;               
                new_v.cgroup_id = bpf_get_current_cgroup_id(); 
                
                bpf_map_update_elem(&resource_map, &k, &new_v, BPF_ANY);
            }
        }
    }

    bpf_map_update_elem(&sched_start, &next_pid, &now, BPF_ANY);
    return 0;
}

// 纯文本协议数据捕获 (stdio + 非SSL TCP)
// 用于监控 MCP stdio transport、A2A/ACP/ANP localhost HTTP
static __always_inline void submit_raw_event(__u32 pid, __u32 fd,
    const char *buf, size_t count, int direction, enum raw_data_source source, __u32 peer) {

    struct process_context *ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!ctx) {
        if (is_behavioral_discovery_enabled() && buf && count > 0) {
            __u8 preview[LLM_FP_SCAN_LEN];
            if (bpf_probe_read_user(preview, sizeof(preview), buf) == 0) {
                if (has_llm_protocol_fingerprint(preview, LLM_FP_SCAN_LEN)) {
                    update_candidate_score(pid, 1);
                    check_and_promote_unknown(pid);
                }
            }
        }
        return;
    }

    struct raw_data_event *event = bpf_ringbuf_reserve(&raw_rb, sizeof(*event), 0);
    if (!event) { inc_drop(DROP_RAW_EVENT); return; }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (__u32)pid_tgid;
    event->agent_id = ctx->agent_id;
    __builtin_memcpy(event->agent_name, ctx->agent_name, MAX_AGENT_NAME_LEN);
    event->parent_agent_id = ctx->parent_agent_id;
    __builtin_memcpy(event->parent_agent_name, ctx->parent_agent_name, MAX_AGENT_NAME_LEN);
    event->direction = direction;
    event->source = source;
    event->fd = fd;
    event->peer_pid = peer;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    size_t copy_size = count;
    if (copy_size > RAW_DATA_BUF_SIZE) copy_size = RAW_DATA_BUF_SIZE;
    event->data_len = (__u32)count;

    if (buf && copy_size > 0) {
        int ret = bpf_probe_read_user(&event->buf, copy_size, buf);
        if (!ret) {
            event->buf_filled = 1;
            event->buf_size = (__u32)copy_size;
        } else {
            event->buf_filled = 0;
            event->buf_size = 0;
        }
    } else {
        event->buf_filled = 0;
        event->buf_size = 0;
    }

    if (ctx->is_sub_agent == CANDIDATE_SUB_AGENT && event->buf_filled &&
        has_agent_protocol_fingerprint(event->buf, event->buf_size)) {
        if (promote_to_sub_agent(pid)) {
            event->agent_id = AGENT_ID_AUTO_DETECT(pid);
        }
    }

    bpf_ringbuf_submit(event, 0);
}

// stdio 监控 (MCP stdio transport)

SEC("ksyscall/read")
int BPF_KSYSCALL(sys_read_stdio, unsigned int fd, char *buf, size_t count) {
    if (fd != 0) return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx) {
        if (!try_auto_register(&monitored_pids)) return 0;
        pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
        if (!pctx) return 0;
    }

    __u32 peer = 0;
    if (pctx->parent_pid != 0) {
        struct process_context *parent_ctx = bpf_map_lookup_elem(&monitored_pids, &pctx->parent_pid);
        if (parent_ctx) {
            peer = pctx->parent_pid;
        }
    }

    struct pending_arg p = {.buf_ptr = (__u64)buf, .fd = fd, .len = count, .peer = peer, .source = RAW_SRC_STDIO};
    bpf_map_update_elem(&pending_read, &tid, &p, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pending_arg *p = bpf_map_lookup_elem(&pending_read, &tid);
    if (!p || ctx->ret <= 0) { bpf_map_delete_elem(&pending_read, &tid); return 0; }

    submit_raw_event(pid, p->fd, (const char *)p->buf_ptr, (size_t)ctx->ret, 0, p->source, p->peer);
    bpf_map_delete_elem(&pending_read, &tid);
    return 0;
}

SEC("ksyscall/write")
int BPF_KSYSCALL(sys_write_raw, unsigned int fd, char *buf, size_t count) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx) {
        if (!try_auto_register(&monitored_pids)) return 0;
        pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
        if (!pctx) return 0;
    }

    __u32 peer = 0;
    if (fd == 1 || fd == 2) {
        if (pctx->parent_pid != 0) {
            struct process_context *parent_ctx = bpf_map_lookup_elem(&monitored_pids, &pctx->parent_pid);
            if (parent_ctx) peer = pctx->parent_pid;
        }
        submit_raw_event(pid, fd, buf, count, 1, RAW_SRC_STDIO, peer);
    } else {
        struct fd_peer_info *fd_peer = bpf_map_lookup_elem(&fd_peer_map, &fd);
        if (fd_peer && fd_peer->peer_pid != pid) peer = fd_peer->peer_pid;
        submit_raw_event(pid, fd, buf, count, 1, RAW_SRC_TCP, peer);
    }

    return 0;
}

SEC("ksyscall/sendto")
int BPF_KSYSCALL(sys_sendto_raw, int fd, char *buf, size_t len, int flags,
                 void *dest_addr, int addr_len) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx) {
        if (!try_auto_register(&monitored_pids)) return 0;
        pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
        if (!pctx) return 0;
    }

    __u32 peer = 0;
    struct fd_peer_info *fd_peer = bpf_map_lookup_elem(&fd_peer_map, &fd);
    if (fd_peer && fd_peer->peer_pid != pid) {
        peer = fd_peer->peer_pid;
    }

    submit_raw_event(pid, fd, buf, len, 1, RAW_SRC_TCP, peer);
    return 0;
}

SEC("ksyscall/recvfrom")
int BPF_KSYSCALL(sys_recvfrom_raw, int fd, char *buf, size_t len, int flags,
                 void *src_addr, int *addr_len) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx) {
        if (!try_auto_register(&monitored_pids)) return 0;
        pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
        if (!pctx) return 0;
    }

    __u32 peer = 0;
    struct fd_peer_info *fd_peer = bpf_map_lookup_elem(&fd_peer_map, &fd);
    if (fd_peer && fd_peer->peer_pid != pid) {
        peer = fd_peer->peer_pid;
    }

    struct pending_arg p = {.buf_ptr = (__u64)buf, .fd = fd, .len = len, .peer = peer, .source = RAW_SRC_TCP};
    bpf_map_update_elem(&pending_recv, &tid, &p, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pending_arg *p = bpf_map_lookup_elem(&pending_recv, &tid);
    if (!p || ctx->ret <= 0) { bpf_map_delete_elem(&pending_recv, &tid); return 0; }

    submit_raw_event(pid, p->fd, (const char *)p->buf_ptr, (size_t)ctx->ret, 0, p->source, p->peer);
    bpf_map_delete_elem(&pending_recv, &tid);
    return 0;
}

// 纯文本 TCP 监控 (localhost HTTP / A2A / ACP / ANP)
static __always_inline int read_msghdr_payload(struct user_msghdr *msg, __u8 *dst, __u32 max_len) {
    if (!msg || max_len == 0) return 0;

    // Step 1: read iovec array pointer (extra level of indirection vs old buggy code)
    struct iovec *iov_ptr = 0;
    if (bpf_probe_read_user(&iov_ptr, sizeof(iov_ptr), &msg->msg_iov) != 0)
        return 0;
    if (!iov_ptr) return 0;

    // Step 2: dereference to get the actual first iovec
    struct iovec iov = {};
    if (bpf_probe_read_user(&iov, sizeof(iov), iov_ptr) != 0)
        return 0;
    if (!iov.iov_base || iov.iov_len == 0)
        return 0;

    // Step 3: read the actual payload data
    size_t copy_len = iov.iov_len;
    if (copy_len > max_len) copy_len = max_len;

    if (bpf_probe_read_user(dst, copy_len, iov.iov_base) != 0)
        return 0;

    return (int)copy_len;
}

// sendmsg/recvmsg 公共处理逻辑
static __always_inline void submit_msghdr_event(int fd, struct user_msghdr *msg, int direction) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx) {
        if (try_auto_register(&monitored_pids)) {
            pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
            if (!pctx) return;
        } else {
            if (is_behavioral_discovery_enabled() && msg) {
                __u8 preview[LLM_FP_SCAN_LEN];
                int payload_len = read_msghdr_payload(msg, preview, sizeof(preview));
                if (payload_len >= 16 && has_llm_protocol_fingerprint(preview, LLM_FP_SCAN_LEN)) {
                    update_candidate_score(pid, 1);
                    check_and_promote_unknown(pid);
                }
            }
            return;
        }
    }

    struct raw_data_event *event = bpf_ringbuf_reserve(&raw_rb, sizeof(*event), 0);
    if (!event) { inc_drop(DROP_MSGHDR_EVENT); return; }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (__u32)pid_tgid;
    event->agent_id = pctx->agent_id;
    __builtin_memcpy(event->agent_name, pctx->agent_name, MAX_AGENT_NAME_LEN);
    event->parent_agent_id = pctx->parent_agent_id;
    __builtin_memcpy(event->parent_agent_name, pctx->parent_agent_name, MAX_AGENT_NAME_LEN);
    event->direction = direction;
    event->source = RAW_SRC_TCP;
    event->fd = fd;

    struct fd_peer_info *peer = bpf_map_lookup_elem(&fd_peer_map, &fd);
    if (peer && peer->peer_pid != pid) {
        event->peer_pid = peer->peer_pid;
    } else {
        event->peer_pid = 0;
    }

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    int payload_len = read_msghdr_payload(msg, event->buf, RAW_DATA_BUF_SIZE);
    if (payload_len > 0) {
        event->buf_filled = 1;
        event->buf_size = (__u32)payload_len;
        event->data_len = (__u32)payload_len;
    } else {
        event->buf_filled = 0;
        event->buf_size = 0;
        event->data_len = 0;
    }

    if (pctx->is_sub_agent == CANDIDATE_SUB_AGENT && event->buf_filled &&
        has_agent_protocol_fingerprint(event->buf, event->buf_size)) {
        if (promote_to_sub_agent(pid)) {
            event->agent_id = AGENT_ID_AUTO_DETECT(pid);
        }
    }

    bpf_ringbuf_submit(event, 0);
}

SEC("ksyscall/sendmsg")
int BPF_KSYSCALL(sys_sendmsg_raw, int fd, struct user_msghdr *msg, int flags) {
    submit_msghdr_event(fd, msg, 1);
    return 0;
}

SEC("ksyscall/recvmsg")
int BPF_KSYSCALL(sys_recvmsg_raw, int fd, struct user_msghdr *msg, int flags) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct process_context *pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!pctx) {
        if (!try_auto_register(&monitored_pids)) return 0;
        pctx = bpf_map_lookup_elem(&monitored_pids, &pid);
        if (!pctx) return 0;
    }

    struct pending_msg_arg p = {.msg_ptr = (__u64)msg, .fd = fd};
    bpf_map_update_elem(&pending_msg, &tid, &p, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct pending_msg_arg *p = bpf_map_lookup_elem(&pending_msg, &tid);
    if (!p || ctx->ret <= 0) { bpf_map_delete_elem(&pending_msg, &tid); return 0; }

    submit_msghdr_event(p->fd, (struct user_msghdr *)p->msg_ptr, 0);
    bpf_map_delete_elem(&pending_msg, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";