#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct proc_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_tree SEC(".maps");

struct ssl_args {
    void *buf;
    __u32 num;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ssl_args);
} pid_ssl_args SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} ssl_events SEC(".maps");

static __always_inline void my_memset(void *s, int c, __u32 n)
{
    __u32 i = 0;
#pragma unroll
    for (i = 0; i < 64 && i < n; i++) {
        ((char *)s)[i] = (char)c;
    }
}

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

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_uprobe, void *ssl, void *buf, __u32 num)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct ssl_args args = {
        .buf = buf,
        .num = num,
    };
    bpf_map_update_elem(&pid_ssl_args, &pid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ssl_write_uretprobe, long ret)
{
    if (ret <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct ssl_args *args_ptr = bpf_map_lookup_elem(&pid_ssl_args, &pid);
    if (!args_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e)
        goto cleanup;
    
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_SSL_WRITE);
    e->ssl_write.bytes = (__u64)ret;
    e->ssl_write.fd = -1;

    if (args_ptr->buf && args_ptr->num > 0) {
        __u32 copy_len = args_ptr->num > MAX_DATA_LEN ? MAX_DATA_LEN : args_ptr->num;
        bpf_probe_read_user_str(e->ssl_write.data, copy_len, args_ptr->buf);
        e->ssl_write.data_len = copy_len;
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&pid_ssl_args, &pid);
    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_uprobe, void *ssl, void *buf, __u32 num)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct ssl_args args = {
        .buf = buf,
        .num = num,
    };
    bpf_map_update_elem(&pid_ssl_args, &pid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_uretprobe, long ret)
{
    if (ret <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct ssl_args *args_ptr = bpf_map_lookup_elem(&pid_ssl_args, &pid);
    if (!args_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e)
        goto cleanup;
    
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_SSL_READ);
    e->ssl_read.bytes = (__u64)ret;
    e->ssl_read.fd = -1;

    if (args_ptr->buf && ret > 0) {
        __u32 copy_len = ret > MAX_DATA_LEN ? MAX_DATA_LEN : ret;
        bpf_probe_read_user_str(e->ssl_read.data, copy_len, args_ptr->buf);
        e->ssl_read.data_len = copy_len;
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&pid_ssl_args, &pid);
    return 0;
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_uprobe, void *ssl, void *buf, __u32 num, __u32 *written)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct ssl_args args = {
        .buf = buf,
        .num = num,
    };
    bpf_map_update_elem(&pid_ssl_args, &pid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int BPF_URETPROBE(ssl_write_ex_uretprobe, long ret)
{
    if (ret <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct ssl_args *args_ptr = bpf_map_lookup_elem(&pid_ssl_args, &pid);
    if (!args_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e)
        goto cleanup;
    
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_SSL_WRITE);
    e->ssl_write.bytes = (__u64)args_ptr->num;
    e->ssl_write.fd = -1;

    if (args_ptr->buf && args_ptr->num > 0) {
        __u32 copy_len = args_ptr->num > MAX_DATA_LEN ? MAX_DATA_LEN : args_ptr->num;
        bpf_probe_read_user_str(e->ssl_write.data, copy_len, args_ptr->buf);
        e->ssl_write.data_len = copy_len;
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&pid_ssl_args, &pid);
    return 0;
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_uprobe, void *ssl, void *buf, __u32 num, __u32 *bytes_read)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct ssl_args args = {
        .buf = buf,
        .num = num,
    };
    bpf_map_update_elem(&pid_ssl_args, &pid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_uretprobe, long ret)
{
    if (ret <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct ssl_args *args_ptr = bpf_map_lookup_elem(&pid_ssl_args, &pid);
    if (!args_ptr)
        return 0;

    __u32 bytes_read_val = 0;
    if (args_ptr->num > 0) {
        bytes_read_val = args_ptr->num;
    }

    struct net_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e)
        goto cleanup;
    
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_SSL_READ);
    e->ssl_read.bytes = (__u64)bytes_read_val;
    e->ssl_read.fd = -1;

    if (args_ptr->buf && bytes_read_val > 0) {
        __u32 copy_len = bytes_read_val > MAX_DATA_LEN ? MAX_DATA_LEN : bytes_read_val;
        bpf_probe_read_user_str(e->ssl_read.data, copy_len, args_ptr->buf);
        e->ssl_read.data_len = copy_len;
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&pid_ssl_args, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";