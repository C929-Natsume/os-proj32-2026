#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>
#include "common.h"

// 定义共享的 Ring Buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline __u32 current_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

// 抽象公共上下文捕获逻辑
static __always_inline struct sys_event* reserve_event(__u32 event_type) {
    struct sys_event *event = bpf_ringbuf_reserve(&rb, sizeof(struct sys_event), 0);
    if (!event) {
        return NULL; // 缓冲区满时安全丢包
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->event_type = event_type;
    event->pid = (__u32)(pid_tgid >> 32); // 提取真实包含线程组的 PID
    event->ppid = current_ppid();
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    return event;
}

SEC("ksyscall/execve")
int BPF_KSYSCALL(sys_execve, const char *filename)
{
    struct sys_event *event = reserve_event(EVENT_EXECVE);
    if (!event) return 0;

    // 安全地从用户态空间读取执行文件名字符串
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("ksyscall/fork")
int BPF_KSYSCALL(sys_fork)
{
    struct sys_event *event = reserve_event(EVENT_FORK);
    if (!event) return 0;

    // fork 主要关注上下文（父进程及生成时机），filename 置空
    event->filename[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("ksyscall/open")
int BPF_KSYSCALL(sys_open, const char *filename, int flags, int mode)
{
    struct sys_event *event = reserve_event(EVENT_OPEN);
    if (!event) return 0;

    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    event->open.mode = (__u32)mode;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("ksyscall/unlink")
int BPF_KSYSCALL(sys_unlink, const char *pathname)
{
    struct sys_event *event = reserve_event(EVENT_UNLINK);
    if (!event) return 0;

    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), pathname);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("ksyscall/connect")
int BPF_KSYSCALL(sys_connect, int sockfd, struct sockaddr *uservaddr, int addrlen)
{
    struct sys_event *event = reserve_event(EVENT_CONNECT);
    if (!event) return 0;

    event->filename[0] = '\0'; // 网络事件不涉及 filename
    
    // 捕获网络连接的底层协议族
    short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &uservaddr->sa_family);
    event->connect.family = (int)family;
    
    // 针对 IPv4 (AF_INET) 提取目标端口与 IP
    if (family == 2) { // AF_INET = 2
        struct sockaddr_in in_addr;
        bpf_probe_read_kernel(&in_addr, sizeof(in_addr), uservaddr);
        
        // 【修复 1】：使用 Clang/GCC 内置的字节反转函数代替 __constant_ntohs
        event->connect.dport = __builtin_bswap16(in_addr.sin_port);
        
        // 【修复 2】：不要在内核态做 snprintf，直接把 4 字节原始 IP 存入 dip
        unsigned char ip[4];
        bpf_probe_read_kernel(&ip, sizeof(ip), &in_addr.sin_addr.s_addr);
        event->connect.dip[0] = ip[0];
        event->connect.dip[1] = ip[1];
        event->connect.dip[2] = ip[2];
        event->connect.dip[3] = ip[3];
        event->connect.dip[4] = '\0'; 
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
