#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *args)
{
    bpf_printk("[BPF] sys_enter captured: id=%d", args->id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *args)
{
    bpf_printk("[BPF] sys_exit captured: id=%d, ret=%d", args->id, args->ret);
    return 0;
}

SEC("kprobe/do_execve")
int BPF_KPROBE(do_execve, const char *filename)
{
    bpf_printk("[BPF] execve detected: filename=%s", filename);
    return 0;
}

SEC("kprobe/__x64_sys_fork")
int BPF_KPROBE(sys_fork)
{
    bpf_printk("[BPF] fork system call detected");
    return 0;
}

SEC("kprobe/__x64_sys_open")
int BPF_KPROBE(sys_open, const char *filename, int flags, int mode)
{
    bpf_printk("[BPF] open syscall: filename=%s, flags=%d, mode=%d", filename, flags, mode);
    return 0;
}

SEC("kprobe/__x64_sys_unlink")
int BPF_KPROBE(sys_unlink, const char *pathname)
{
    bpf_printk("[BPF] unlink syscall: pathname=%s", pathname);
    return 0;
}

SEC("kprobe/__x64_sys_connect")
int BPF_KPROBE(sys_connect, int sockfd, struct sockaddr *uservaddr, int addrlen)
{
    bpf_printk("[BPF] connect syscall: sockfd=%d, addrlen=%d", sockfd, addrlen);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
