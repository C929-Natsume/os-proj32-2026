#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include "common.h"

// 数据传输管道
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ssl_rb SEC(".maps");

// 状态暂存哈希表：用于在 SSL_read 的入口和出口之间传递 buf 指针
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);     // 使用 PID 作为 Key
    __type(value, void *);  // 暂存 buf 的内存地址
} active_read_args SEC(".maps");

SEC("uprobe/libssl.so.3:SSL_read")
int ssl_read_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    void *buf = (void *)PT_REGS_PARM2(ctx);
    
    // 在进入函数时，把 buf 的地址存入 Hash Map
    bpf_map_update_elem(&active_read_args, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/libssl.so.3:SSL_read")
int ssl_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx); // 实际读取到的字节数
    void **buf_ptr;

    // 如果读取失败或没有数据，清理 Map 并退出
    if (ret <= 0) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    // 找回我们在 uprobe 存下的 buf 指针
    buf_ptr = bpf_map_lookup_elem(&active_read_args, &pid_tgid);
    if (!buf_ptr) return 0;

    struct ssl_event *event = bpf_ringbuf_reserve(&ssl_rb, sizeof(*event), 0);
    if (event) {
        event->event_type = EVENT_SSL_READ;
        event->pid = pid_tgid >> 32;
        event->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        // 防越界保护：最多只读结构体允许的 4095 字节
        __u32 len = (ret > sizeof(event->data) - 1) ? sizeof(event->data) - 1 : ret;
        event->data_len = len;
        
        // 【核心动作】从用户态进程的内存中，把解密后的明文偷出来！
        bpf_probe_read_user(&event->data, len, *buf_ptr);
        event->data[len] = '\0'; // 确保字符串安全截断
        
        bpf_ringbuf_submit(event, 0);
    }

    // 善后清理
    bpf_map_delete_elem(&active_read_args, &pid_tgid);
    return 0;
}

SEC("uprobe/libssl.so.3:SSL_write")
int ssl_write_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    void *buf = (void *)PT_REGS_PARM2(ctx); // 准备发送的明文
    int num = (int)PT_REGS_PARM3(ctx);      // 准备发送的长度

    if (num <= 0) return 0;

    // Write 操作在入口处 buf 就已经有数据了，直接偷取
    struct ssl_event *event = bpf_ringbuf_reserve(&ssl_rb, sizeof(*event), 0);
    if (event) {
        event->event_type = EVENT_SSL_WRITE;
        event->pid = pid_tgid >> 32;
        event->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        __u32 len = (num > sizeof(event->data) - 1) ? sizeof(event->data) - 1 : num;
        event->data_len = len;
        bpf_probe_read_user(&event->data, len, buf);
        event->data[len] = '\0';
        
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";