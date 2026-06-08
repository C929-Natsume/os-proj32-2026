#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
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

// 自适应判定引擎
static __always_inline bool should_monitor(__u32 pid) {
    struct process_context *ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (ctx) return true;
    return try_auto_register(&monitored_pids);
}

static __always_inline void submit_sys_event(__u32 event_type, __u64 pid_tgid, const char *filename) {
    __u32 pid = pid_tgid >> 32;
    
    // 查找该进程所属的智能体上下文
    struct process_context *ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!ctx) {
        if (is_claude_target()) {
            ctx = bpf_map_lookup_elem(&monitored_pids, &pid);
            if (!ctx) return;
        } else {
            return;
        }
    }

    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) return;

    event->event_type = event_type;
    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->child_pid = 0; 

    // 将查到的身份信息注入到传给用户态的事件中
    event->agent_id = ctx->agent_id;
    __builtin_memcpy(event->agent_name, ctx->agent_name, MAX_AGENT_NAME_LEN);

    if (filename) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    } else {
        event->filename[0] = '\0';
    }

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
    submit_sys_event(EVENT_CONNECT, bpf_get_current_pid_tgid(), NULL);
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

    // 查找父进程的上下文
    struct process_context *parent_ctx = bpf_map_lookup_elem(&monitored_pids, &parent_pid);
    if (!parent_ctx) return 0;

    __u32 child_pid = ctx->child_pid; 

    // 子进程写入监控名册
    struct process_context child_ctx = {0};
    child_ctx.agent_id = parent_ctx->agent_id; 
    __builtin_memcpy(child_ctx.agent_name, parent_ctx->agent_name, MAX_AGENT_NAME_LEN);
    child_ctx.parent_pid = parent_pid;
    child_ctx.depth = parent_ctx->depth + 1;
    child_ctx.is_sub_agent = 0; // 默认视为普通系统工具

    bpf_map_update_elem(&monitored_pids, &child_pid, &child_ctx, BPF_ANY);

    // trace 进行语义上下文的继承
    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) return 0;

    event->event_type = EVENT_FORK;
    event->pid = parent_pid; 
    event->child_pid = child_pid;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    
    event->agent_id = parent_ctx->agent_id;
    __builtin_memcpy(event->agent_name, parent_ctx->agent_name, MAX_AGENT_NAME_LEN);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 资源占用监控
SEC("tp_btf/sched_switch")
int BPF_PROG(trace_sched_switch_btf, bool preempt, struct task_struct *prev, struct task_struct *next) {
    __u32 prev_pid = prev->pid;
    __u32 next_pid = next->pid;
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

char LICENSE[] SEC("license") = "GPL";