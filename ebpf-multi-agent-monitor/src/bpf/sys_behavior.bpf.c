#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 1. Tracepoint 探针 (处理 sys_enter)
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(void *ctx)
{
    // 在函数内部进行强制类型转换，绕过内核 BTF 校验
    struct trace_event_raw_sys_enter *args = (struct trace_event_raw_sys_enter *)ctx;
    bpf_printk("[BPF] sys_enter captured: id=%d", args->id);
    return 0;
}

// 2. Tracepoint 探针 (处理 sys_exit)
SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(void *ctx)
{
    // 在函数内部进行强制类型转换
    struct trace_event_raw_sys_exit *args = (struct trace_event_raw_sys_exit *)ctx;
    bpf_printk("[BPF] sys_exit captured: id=%d, ret=%d", args->id, args->ret);
    return 0;
}

// =======================================================
// 现代化 ksyscall 探针写法
// 注意：1. SEC 名字直接用短名即可 (libbpf 自动匹配 __x64_sys_...)
//       2. BPF_KSYSCALL 直接接收原始的系统调用参数，拒绝 pt_regs!
// =======================================================

SEC("ksyscall/execve")
int BPF_KSYSCALL(sys_execve, const char *filename)
{
    bpf_printk("[BPF] execve detected: filename=%s", filename);
    return 0;
}

SEC("ksyscall/fork")
int BPF_KSYSCALL(sys_fork)
{
    bpf_printk("[BPF] fork system call detected");
    return 0;
}

SEC("ksyscall/open")
int BPF_KSYSCALL(sys_open, const char *filename, int flags, int mode)
{
    bpf_printk("[BPF] open syscall: filename=%s, flags=%d, mode=%d", filename, flags, mode);
    return 0;
}

SEC("ksyscall/unlink")
int BPF_KSYSCALL(sys_unlink, const char *pathname)
{
    bpf_printk("[BPF] unlink syscall: pathname=%s", pathname);
    return 0;
}

SEC("ksyscall/connect")
int BPF_KSYSCALL(sys_connect, int sockfd, struct sockaddr *uservaddr, int addrlen)
{
    bpf_printk("[BPF] connect syscall: sockfd=%d, addrlen=%d", sockfd, addrlen);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";