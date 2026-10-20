#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/* ---------- 共享的 pid_tree，使用 pinning 以便其他程序访问 ---------- */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // pid
    __type(value, struct proc_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_tree SEC(".maps");

/* ---------- 进程事件 ring buffer ---------- */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} proc_events SEC(".maps");

static __always_inline void bpf_memset(void *s, int c, __u32 n)
{
    for (__u32 i = 0; i < n; i++)
        ((char *)s)[i] = (char)c;
}

/* 填充公共头 */
static __always_inline void fill_header(struct event_header *hdr, int cat, int type)
{
    hdr->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    hdr->pid = pid_tgid >> 32;
    hdr->tid = (__u32)pid_tgid;
    hdr->category = cat;
    hdr->type = type;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

/* ========== EXECVE ========== */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_PROC, PROC_EXEC);

    char *filename = (char *)ctx->args[0];
    long ret = bpf_probe_read_user_str(e->exec.filename, MAX_FILENAME, filename);
    if (ret < 0)
        goto discard;

    // 查找父进程
    __u32 pid = e->hdr.pid;
    struct proc_info *info = bpf_map_lookup_elem(&pid_tree, &pid);
    e->exec.parent_pid = info ? info->parent_pid : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;

discard:
    bpf_ringbuf_discard(e, 0);
    return 0;
}

/* ========== CLONE (FORK/VFORK) ========== */
SEC("tracepoint/syscalls/sys_exit_clone")
int trace_clone(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid = pid_tgid >> 32;
    __u32 child_pid = (__u32)ret;

    // 记录 pid_tree
    struct proc_info info = {0};
    info.parent_pid = parent_pid;
    bpf_get_current_comm(&info.comm, TASK_COMM_LEN);
    bpf_map_update_elem(&pid_tree, &child_pid, &info, BPF_ANY);

    // 发送事件
    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_PROC, PROC_FORK);
    e->hdr.pid = parent_pid; // 事件归属父进程
    e->fork.parent_pid = parent_pid;
    e->fork.child_pid = child_pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ========== PROCESS EXIT ========== */
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_PROC, PROC_EXIT);
    e->hdr.pid = ctx->pid;
    e->exit.exit_code = 0;
    bpf_ringbuf_submit(e, 0);

    __u32 pid = ctx->pid;
    bpf_map_delete_elem(&pid_tree, &pid);
    return 0;
}

/* ========== SIGNAL GENERATE ========== */
SEC("tracepoint/signal/signal_generate")
int trace_signal_generate(struct trace_event_raw_signal_generate *ctx)
{
    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_PROC, PROC_SIGNAL);
    e->signal.sig = ctx->sig;
    e->signal.target_pid = ctx->pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ========== SETUID ========== */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_PROC, PROC_SETUID);
    e->setuid.uid = (__u32)ctx->args[0];
    e->setuid.old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // current uid
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";