#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ssl_rb SEC(".maps");

// 将目标库指定为 libssl.so.3
SEC("uprobe/libssl.so.3:SSL_read")
int ssl_read_enter(struct pt_regs *ctx)
{
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    bpf_printk("[BPF] SSL_read uprobe triggered: ssl=%px, num=%d", ssl, num);
    return 0;
}

SEC("uretprobe/libssl.so.3:SSL_read")
int ssl_read_exit(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    bpf_printk("[BPF] SSL_read uretprobe: ret=%d", ret);
    return 0;
}

SEC("uprobe/libssl.so.3:SSL_write")
int ssl_write_enter(struct pt_regs *ctx)
{
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    bpf_printk("[BPF] SSL_write uprobe triggered: ssl=%px, num=%d", ssl, num);
    return 0;
}

SEC("uretprobe/libssl.so.3:SSL_write")
int ssl_write_exit(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    bpf_printk("[BPF] SSL_write uretprobe: ret=%d", ret);
    return 0;
}

SEC("uprobe/libssl.so.3:SSL_connect")
int ssl_connect_enter(struct pt_regs *ctx)
{
    int fd = (int)PT_REGS_PARM1(ctx);
    bpf_printk("[BPF] SSL_connect uprobe: fd=%d", fd);
    return 0;
}

SEC("uprobe/libssl.so.3:SSL_accept")
int ssl_accept_enter(struct pt_regs *ctx)
{
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    bpf_printk("[BPF] SSL_accept uprobe: ssl=%px", ssl);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";