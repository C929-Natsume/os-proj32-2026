#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "net.skel.h"
#include "proc_tree.h"
#include "common.h"

static char *format_ip_addr(struct ip_addr *addr, char *buf, size_t buf_len)
{
    if (!addr) {
        snprintf(buf, buf_len, "unknown");
        return buf;
    }
    
    if (addr->family == AF_INET) {
        struct in_addr in = {.s_addr = addr->addr.v4};
        inet_ntop(AF_INET, &in, buf, buf_len);
    } else if (addr->family == AF_INET6) {
        inet_ntop(AF_INET6, addr->addr.v6, buf, buf_len);
    } else {
        snprintf(buf, buf_len, "family=%u", addr->family);
    }
    return buf;
}

static void print_data_content(const char *data, __u32 len)
{
    if (len == 0)
        return;
    
    log_print("  Data: ");
    for (__u32 i = 0; i < len; i++) {
        if (data[i] >= 32 && data[i] <= 126)
            log_print("%c", data[i]);
        else
            log_print(".");
    }
    log_print("\n");
}

int handle_net_event(void *ctx, void *data, size_t data_sz)
{
    struct net_event *e = data;
    char addr_buf[INET6_ADDRSTRLEN];

    if (!is_claude_related(e->hdr.pid))
        return 0;

    switch (e->hdr.type)
    {
    case NET_CONNECT:
        log_print("[%llu] PID %d (%s) CONNECT fd=%d %s:%u\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->connect.fd, format_ip_addr(&e->connect.saddr, addr_buf, sizeof(addr_buf)),
                  ntohs(e->connect.sport));
        break;
    case NET_TCP_STATE:
        log_print("[%llu] PID %d (%s) TCP STATE %s:%u -> %s:%u state=%d->%d\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  format_ip_addr(&e->tcp_state.saddr, addr_buf, sizeof(addr_buf)),
                  ntohs(e->tcp_state.sport),
                  format_ip_addr(&e->tcp_state.daddr, addr_buf, sizeof(addr_buf)),
                  ntohs(e->tcp_state.dport),
                  e->tcp_state.oldstate, e->tcp_state.newstate);
        break;
    case NET_SOCKET:
        log_print("[%llu] PID %d (%s) SOCKET domain=%u type=%u proto=%u fd=%d\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->socket.domain, e->socket.type, e->socket.protocol, e->socket.fd);
        break;
    case NET_BIND:
        log_print("[%llu] PID %d (%s) BIND fd=%d %s:%u\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->bind.fd, format_ip_addr(&e->bind.saddr, addr_buf, sizeof(addr_buf)),
                  ntohs(e->bind.sport));
        break;
    case NET_LISTEN:
        log_print("[%llu] PID %d (%s) LISTEN fd=%d backlog=%d\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->listen.fd, e->listen.backlog);
        break;
    case NET_ACCEPT:
        log_print("[%llu] PID %d (%s) ACCEPT fd=%d newfd=%d\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->accept.fd, e->accept.newfd);
        break;
    case NET_SEND:
        log_print("[%llu] PID %d (%s) SEND fd=%d bytes=%llu\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->send.fd, e->send.bytes);
        if (e->send.data_len > 0) {
            print_data_content(e->send.data, e->send.data_len);
        }
        break;
    case NET_RECV:
        log_print("[%llu] PID %d (%s) RECV fd=%d bytes=%llu\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->recv.fd, e->recv.bytes);
        if (e->recv.data_len > 0) {
            print_data_content(e->recv.data, e->recv.data_len);
        }
        break;
    case NET_CLOSE:
        log_print("[%llu] PID %d (%s) CLOSE fd=%d\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->close.fd);
        break;
    case NET_SENDTO:
        log_print("[%llu] PID %d (%s) SENDTO fd=%d %s:%u bytes=%llu\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->sendto.fd, format_ip_addr(&e->sendto.daddr, addr_buf, sizeof(addr_buf)),
                  ntohs(e->sendto.dport), e->sendto.bytes);
        if (e->sendto.data_len > 0) {
            print_data_content(e->sendto.data, e->sendto.data_len);
        }
        break;
    case NET_RECVFROM:
        log_print("[%llu] PID %d (%s) RECVFROM fd=%d %s:%u bytes=%llu\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->recvfrom.fd, format_ip_addr(&e->recvfrom.saddr, addr_buf, sizeof(addr_buf)),
                  ntohs(e->recvfrom.sport), e->recvfrom.bytes);
        if (e->recvfrom.data_len > 0) {
            print_data_content(e->recvfrom.data, e->recvfrom.data_len);
        }
        break;
    default:
        log_print("[%llu] PID %d (%s) UNKNOWN net type %d\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->hdr.type);
    }
    return 0;
}