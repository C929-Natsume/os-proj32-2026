#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "net.skel.h"
#include "proc_tree.h"
#include "intra_analyzer.h"

static int demo_all_enabled(void)
{
    const char *v = getenv("MONITOR_DEMO_ALL");
    return v && (v[0] == '1' || v[0] == 'y' || v[0] == 'Y');
}

int handle_net_event(void *ctx, void *data, size_t data_sz)
{
    struct net_event *e = data;

    // claude
    if (!demo_all_enabled() && !is_claude_related(e->hdr.pid))
        return 0;

    intra_on_net_event(e);

    // printf("[%llu] PID %d (%s) ", e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm);
    switch (e->hdr.type)
    {
    case NET_CONNECT:
    {
        char addr_buf[INET_ADDRSTRLEN] = "unknown";
        inet_ntop(AF_INET, &e->connect.saddr, addr_buf, sizeof(addr_buf));
        printf("CONNECT fd=%d %s:%u\n", e->connect.fd,
               addr_buf, ntohs(e->connect.sport));
        break;
    }
    case NET_TCP_STATE:
    {
        char saddr_buf[INET_ADDRSTRLEN] = "unknown";
        char daddr_buf[INET_ADDRSTRLEN] = "unknown";
        inet_ntop(AF_INET, &e->tcp_state.saddr, saddr_buf, sizeof(saddr_buf));
        inet_ntop(AF_INET, &e->tcp_state.daddr, daddr_buf, sizeof(daddr_buf));
        printf("TCP STATE %s:%u -> %s:%u %d -> %d\n",
               saddr_buf, ntohs(e->tcp_state.sport),
               daddr_buf, ntohs(e->tcp_state.dport),
               e->tcp_state.oldstate, e->tcp_state.newstate);
        break;
    }
    case NET_SOCKET:
        printf("SOCKET domain=%u type=%u proto=%u fd=%d\n",
               e->socket.domain, e->socket.type, e->socket.protocol, e->socket.fd);
        break;
    case NET_BIND:
    {
        char addr_buf[INET_ADDRSTRLEN] = "unknown";
        inet_ntop(AF_INET, &e->bind.saddr, addr_buf, sizeof(addr_buf));
        printf("BIND fd=%d %s:%u\n", e->bind.fd,
               addr_buf, ntohs(e->bind.sport));
        break;
    }
    case NET_LISTEN:
        printf("LISTEN fd=%d backlog=%d\n", e->listen.fd, e->listen.backlog);
        break;
    case NET_ACCEPT:
        printf("ACCEPT fd=%d newfd=%d\n", e->accept.fd, e->accept.newfd);
        break;
    case NET_SEND:
        printf("SEND fd=%d bytes=%llu\n", e->send.fd, e->send.bytes);
        break;
    case NET_RECV:
        printf("RECV fd=%d bytes=%llu\n", e->recv.fd, e->recv.bytes);
        break;
    case NET_CLOSE:
        printf("CLOSE fd=%d\n", e->close.fd);
        break;
    default:
        printf("UNKNOWN net type %d\n", e->hdr.type);
    }
    return 0;
}
