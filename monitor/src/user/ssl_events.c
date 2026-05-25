#include <stdio.h>
#include <arpa/inet.h>
#include "ssl.skel.h"
#include "proc_tree.h"
#include "common.h"

static void print_hex_data(const char *data, __u32 len)
{
    if (len == 0)
        return;

    for (__u32 i = 0; i < len; i++) {
        if (data[i] >= 32 && data[i] <= 126)
            printf("%c", data[i]);
        else
            printf(".");
    }
}



int handle_ssl_event(void *ctx, void *data, size_t data_sz)
{
    struct net_event *e = data;

    if (!is_claude_related(e->hdr.pid))
        return 0;

    switch (e->hdr.type)
    {
    case NET_SSL_WRITE:
        log_print("[%llu] PID %d (%s) SSL_WRITE bytes=%llu data_len=%u\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->ssl_write.bytes, e->ssl_write.data_len);
        if (e->ssl_write.data_len > 0) {
            log_print("  Data: ");
            print_hex_data(e->ssl_write.data, e->ssl_write.data_len);
            log_print("\n");
        }
        break;
    case NET_SSL_READ:
        log_print("[%llu] PID %d (%s) SSL_READ bytes=%llu data_len=%u\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->ssl_read.bytes, e->ssl_read.data_len);
        if (e->ssl_read.data_len > 0) {
            log_print("  Data: ");
            print_hex_data(e->ssl_read.data, e->ssl_read.data_len);
            log_print("\n");
        }
        break;
    default:
        log_print("[%llu] PID %d (%s) UNKNOWN ssl type %d\n",
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm,
                  e->hdr.type);
    }
    return 0;
}