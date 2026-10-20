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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct fd_key);
    __type(value, struct sock_info);
} fd_sock_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} pid_fd_map SEC(".maps");

struct socket_args {
    __u32 domain;
    __u32 type;
    __u32 protocol;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct socket_args);
} pid_socket_args SEC(".maps");

struct sendto_args {
    void *buf;
    __u32 len;
    struct sockaddr *addr;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct sendto_args);
} pid_sendto_args SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} net_events SEC(".maps");

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

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct socket_args args = {
        .domain = (__u32)ctx->args[0],
        .type = (__u32)ctx->args[1],
        .protocol = (__u32)ctx->args[2],
    };
    bpf_map_update_elem(&pid_socket_args, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_socket_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct socket_args *args_ptr = bpf_map_lookup_elem(&pid_socket_args, &pid);
    if (!args_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_SOCKET);
    e->socket.fd = (int)ret;
    e->socket.domain = args_ptr->domain;
    e->socket.type = args_ptr->type;
    e->socket.protocol = args_ptr->protocol;
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pid_socket_args, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_CONNECT);
    int fd = (int)ctx->args[0];
    e->connect.fd = fd;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    struct sockaddr_in sa;

    bpf_probe_read_user(&sa, sizeof(sa), addr);
    if (sa.sin_family == AF_INET) {
        e->connect.saddr.family = AF_INET;
        e->connect.saddr.addr.v4 = sa.sin_addr.s_addr;
        e->connect.sport = sa.sin_port;
        e->connect.family = AF_INET;
    } else if (sa.sin_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
        e->connect.saddr.family = AF_INET6;
        bpf_probe_read_user(e->connect.saddr.addr.v6, 16, &sa6->sin6_addr);
        bpf_probe_read_user(&e->connect.sport, sizeof(e->connect.sport), &sa6->sin6_port);
        e->connect.family = AF_INET6;
    } else {
        e->connect.saddr.family = sa.sin_family;
        e->connect.family = sa.sin_family;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_BIND);
    e->bind.fd = (int)ctx->args[0];

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    struct sockaddr_in sa;

    bpf_probe_read_user(&sa, sizeof(sa), addr);
    if (sa.sin_family == AF_INET) {
        e->bind.saddr.family = AF_INET;
        e->bind.saddr.addr.v4 = sa.sin_addr.s_addr;
        e->bind.sport = sa.sin_port;
        e->bind.family = AF_INET;
    } else if (sa.sin_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
        e->bind.saddr.family = AF_INET6;
        bpf_probe_read_user(e->bind.saddr.addr.v6, 16, &sa6->sin6_addr);
        bpf_probe_read_user(&e->bind.sport, sizeof(e->bind.sport), &sa6->sin6_port);
        e->bind.family = AF_INET6;
    } else {
        e->bind.saddr.family = sa.sin_family;
        e->bind.family = sa.sin_family;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_LISTEN);
    e->listen.fd = (int)ctx->args[0];
    e->listen.backlog = (int)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];
    bpf_map_update_elem(&pid_fd_map, &pid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *fd_ptr = bpf_map_lookup_elem(&pid_fd_map, &pid);
    if (!fd_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_ACCEPT);
    e->accept.newfd = (int)ret;
    e->accept.fd = (int)*fd_ptr;
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pid_fd_map, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];
    bpf_map_update_elem(&pid_fd_map, &pid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_sendmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *fd_ptr = bpf_map_lookup_elem(&pid_fd_map, &pid);
    if (!fd_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_SEND);
    e->send.fd = (int)*fd_ptr;
    e->send.bytes = (__u64)ret;
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pid_fd_map, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_recvmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];
    bpf_map_update_elem(&pid_fd_map, &pid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_recvmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 *fd_ptr = bpf_map_lookup_elem(&pid_fd_map, &pid);
    if (!fd_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_RECV);
    e->recv.fd = (int)*fd_ptr;
    e->recv.bytes = (__u64)ret;
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pid_fd_map, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct sendto_args args;
    args.len = (__u32)ctx->args[2];
    args.buf = (void *)ctx->args[1];
    args.addr = (struct sockaddr *)ctx->args[4];
    
    bpf_map_update_elem(&pid_sendto_args, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sendto_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct sendto_args *args_ptr = bpf_map_lookup_elem(&pid_sendto_args, &pid);
    if (!args_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        goto cleanup;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_SENDTO);
    e->sendto.fd = -1;
    e->sendto.bytes = (__u64)ret;

    if (args_ptr->addr && args_ptr->len > 0) {
        struct sockaddr_in sa;
        
        bpf_probe_read_user(&sa, sizeof(sa), args_ptr->addr);
        if (sa.sin_family == AF_INET) {
            e->sendto.daddr.family = AF_INET;
            e->sendto.daddr.addr.v4 = sa.sin_addr.s_addr;
            e->sendto.dport = sa.sin_port;
        } else if (sa.sin_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)args_ptr->addr;
            e->sendto.daddr.family = AF_INET6;
            bpf_probe_read_user(e->sendto.daddr.addr.v6, 16, &sa6->sin6_addr);
            bpf_probe_read_user(&e->sendto.dport, sizeof(e->sendto.dport), &sa6->sin6_port);
        } else {
            e->sendto.daddr.family = sa.sin_family;
        }

        __u32 copy_len = args_ptr->len > MAX_DATA_LEN ? MAX_DATA_LEN : args_ptr->len;
        bpf_probe_read_user_str(e->sendto.data, copy_len, args_ptr->buf);
        e->sendto.data_len = copy_len;
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&pid_sendto_args, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct sendto_args args;
    args.len = (__u32)ctx->args[2];
    args.buf = (void *)ctx->args[1];
    args.addr = (struct sockaddr *)ctx->args[4];
    
    bpf_map_update_elem(&pid_sendto_args, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct sendto_args *args_ptr = bpf_map_lookup_elem(&pid_sendto_args, &pid);
    if (!args_ptr)
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        goto cleanup;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_RECVFROM);
    e->recvfrom.fd = -1;
    e->recvfrom.bytes = (__u64)ret;

    if (args_ptr->addr && args_ptr->len > 0) {
        struct sockaddr_in sa;
        
        bpf_probe_read_user(&sa, sizeof(sa), args_ptr->addr);
        if (sa.sin_family == AF_INET) {
            e->recvfrom.saddr.family = AF_INET;
            e->recvfrom.saddr.addr.v4 = sa.sin_addr.s_addr;
            e->recvfrom.sport = sa.sin_port;
        } else if (sa.sin_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)args_ptr->addr;
            e->recvfrom.saddr.family = AF_INET6;
            bpf_probe_read_user(e->recvfrom.saddr.addr.v6, 16, &sa6->sin6_addr);
            bpf_probe_read_user(&e->recvfrom.sport, sizeof(e->recvfrom.sport), &sa6->sin6_port);
        } else {
            e->recvfrom.saddr.family = sa.sin_family;
        }

        __u32 copy_len = ret > MAX_DATA_LEN ? MAX_DATA_LEN : ret;
        bpf_probe_read_user_str(e->recvfrom.data, copy_len, args_ptr->buf);
        e->recvfrom.data_len = copy_len;
    }

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&pid_sendto_args, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_net_close(struct trace_event_raw_sys_enter *ctx)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_CLOSE);
    e->close.fd = (int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    my_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_NET, NET_TCP_STATE);
    
    e->tcp_state.saddr.family = AF_INET;
    __builtin_memcpy(&e->tcp_state.saddr.addr.v4, ctx->saddr, sizeof(ctx->saddr));
    e->tcp_state.sport = ctx->sport;
    
    e->tcp_state.daddr.family = AF_INET;
    __builtin_memcpy(&e->tcp_state.daddr.addr.v4, ctx->daddr, sizeof(ctx->daddr));
    e->tcp_state.dport = ctx->dport;
    
    e->tcp_state.oldstate = ctx->oldstate;
    e->tcp_state.newstate = ctx->newstate;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";