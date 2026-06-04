#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include "common.h"
#include "filter.h"

// ================= 数据传输管道 =================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// ================= 追踪 =================
// 解决 os.system 产生 sh 和 cat 等子进程导致名字改变、被白名单误杀的问题
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // 进程 PID
    __type(value, __u8);  // 是否受监控标志
} monitored_pids SEC(".maps");

// 自适应判定引擎
static __always_inline bool should_monitor(__u32 pid) {
    // 1. 如果在血缘名册里，直接放行（无视它的进程名叫什么）
    __u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (is_monitored && *is_monitored == 1) {
        return true;
    }
    
    // 2. 如果不在名册里，但进程名符合原始母体特征 (python/claude/node)，把它加入名册
    if (is_claude_target()) {
        __u8 val = 1;
        bpf_map_update_elem(&monitored_pids, &pid, &val, BPF_ANY);
        return true;
    }
    
    return false;
}

// ================= 辅助函数 =================
static __always_inline void submit_sys_event(__u32 event_type, __u64 pid_tgid, const char *filename) {
    __u32 pid = pid_tgid >> 32;
    
    // 【核心拦截】：使用血缘名册进行判断
    if (!should_monitor(pid)) return; 

    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) return;

    event->event_type = event_type;
    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->child_pid = 0; 

    if (filename) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    } else {
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
}

// ================= 1. 命令执行监控 =================
SEC("ksyscall/execve")
int BPF_KSYSCALL(sys_execve, const char *filename, const char *const *argv, const char *const *envp) {
    submit_sys_event(EVENT_EXECVE, bpf_get_current_pid_tgid(), filename);
    return 0;
}

// ================= 2. 文件打开监控 =================
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

// ================= 3. 文件删除监控 =================
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

// ================= 4. 底层网络连接监控 =================
SEC("ksyscall/connect")
int BPF_KSYSCALL(sys_connect, int fd, struct sockaddr *uservaddr, int addrlen) {
    submit_sys_event(EVENT_CONNECT, bpf_get_current_pid_tgid(), NULL);
    return 0;
}

// ================= 5. 文件权限修改监控 =================
SEC("ksyscall/fchmodat")
int BPF_KSYSCALL(sys_fchmodat, int dfd, const char *filename, umode_t mode) {
    if (!should_monitor(bpf_get_current_pid_tgid() >> 32)) return 0;
    submit_sys_event(EVENT_CHMOD, bpf_get_current_pid_tgid(), filename);
    return 0;
}

// ================= 6. 进程树监控 =================
SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid = pid_tgid >> 32;

    // 只有在名册里的父亲，才有资格传承血缘
    if (!should_monitor(parent_pid)) return 0;

    __u32 child_pid = ctx->child_pid; 

    // 将子进程的 PID 写入监控名册
    __u8 val = 1;
    bpf_map_update_elem(&monitored_pids, &child_pid, &val, BPF_ANY);

    // 通知 trace 进行语义上下文的继承
    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) return 0;

    event->event_type = EVENT_FORK;
    event->pid = parent_pid; 
    event->child_pid = child_pid;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";