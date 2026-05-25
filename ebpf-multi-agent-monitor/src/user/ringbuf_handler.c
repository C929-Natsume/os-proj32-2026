#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <ringbuf.h>
#include "sys_behavior.skel.h"
#include "ssl_sniffer.skel.h"
#include "common.h"

static volatile int running = 1;

void signal_handler(int sig)
{
    printf("[RINGBUF] Received signal %d, stopping ring buffer polling...\n", sig);
    running = 0;
}

static int handle_sys_event(void *ctx, void *data, size_t len)
{
    if (len != sizeof(struct sys_event)) {
        printf("[RINGBUF] Invalid sys_event size: %zu\n", len);
        return 1;
    }

    struct sys_event *event = data;

    printf("[RINGBUF] Received sys_event: type=%u, pid=%u, comm=%s\n",
           event->event_type, event->pid, event->comm);

    switch (event->event_type) {
    case EVENT_EXECVE:
        printf("[RINGBUF]   -> execve: filename=%s\n", event->filename);
        break;
    case EVENT_FORK:
        printf("[RINGBUF]   -> fork event\n");
        break;
    case EVENT_OPEN:
        printf("[RINGBUF]   -> open: filename=%s, mode=%u\n",
               event->filename, event->open.mode);
        break;
    case EVENT_UNLINK:
        printf("[RINGBUF]   -> unlink: filename=%s\n", event->filename);
        break;
    case EVENT_CONNECT:
        printf("[RINGBUF]   -> connect: family=%d, dport=%d, dip=%s\n",
               event->connect.family, event->connect.dport, event->connect.dip);
        break;
    default:
        printf("[RINGBUF]   -> unknown event type\n");
        break;
    }

    return 0;
}

static int handle_ssl_event(void *ctx, void *data, size_t len)
{
    if (len != sizeof(struct ssl_event)) {
        printf("[RINGBUF] Invalid ssl_event size: %zu\n", len);
        return 1;
    }

    struct ssl_event *event = data;

    printf("[RINGBUF] Received ssl_event: type=%u, pid=%u, comm=%s, data_len=%u\n",
           event->event_type, event->pid, event->comm, event->data_len);

    if (event->event_type == EVENT_SSL_READ) {
        printf("[RINGBUF]   -> SSL_read: %u bytes\n", event->data_len);
    } else if (event->event_type == EVENT_SSL_WRITE) {
        printf("[RINGBUF]   -> SSL_write: %u bytes\n", event->data_len);
    }

    return 0;
}

int main(int argc, char **argv)
{
    printf("[RINGBUF] Ring Buffer Handler starting...\n");

    printf("[RINGBUF] Loading BPF skeletons...\n");
    struct sys_behavior_bpf *sys_skel = sys_behavior_bpf__open_and_load();
    if (!sys_skel) {
        fprintf(stderr, "[RINGBUF] Failed to load sys_behavior BPF\n");
        return 1;
    }

    struct ssl_sniffer_bpf *ssl_skel = ssl_sniffer_bpf__open_and_load();
    if (!ssl_skel) {
        fprintf(stderr, "[RINGBUF] Failed to load ssl_sniffer BPF\n");
        return 1;
    }

    printf("[RINGBUF] Attaching BPF programs...\n");
    sys_behavior_bpf__attach(sys_skel);
    ssl_sniffer_bpf__attach(ssl_skel);

    printf("[RINGBUF] Setting up ring buffer polling...\n");

    struct ring_buffer *sys_rb = ring_buffer__new(
        bpf_map__fd(sys_skel->maps.rb),
        handle_sys_event,
        NULL,
        NULL);

    struct ring_buffer *ssl_rb = ring_buffer__new(
        bpf_map__fd(ssl_skel->maps.ssl_rb),
        handle_ssl_event,
        NULL,
        NULL);

    if (!sys_rb || !ssl_rb) {
        fprintf(stderr, "[RINGBUF] Failed to create ring buffers\n");
        return 1;
    }

    printf("[RINGBUF] Ring buffers ready, polling for events...\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while (running) {
        printf("[RINGBUF] Polling ring buffers...\n");
        int err = ring_buffer__poll(sys_rb, 1000);
        if (err < 0 && err != -EINTR) {
            printf("[RINGBUF] Error polling sys_rb: %d\n", err);
        }

        err = ring_buffer__poll(ssl_rb, 1000);
        if (err < 0 && err != -EINTR) {
            printf("[RINGBUF] Error polling ssl_rb: %d\n", err);
        }
    }

    printf("[RINGBUF] Shutting down ring buffer handler...\n");
    ring_buffer__free(sys_rb);
    ring_buffer__free(ssl_rb);
    sys_behavior_bpf__destroy(sys_skel);
    ssl_sniffer_bpf__destroy(ssl_skel);
    printf("[RINGBUF] Ring buffer handler shutdown complete\n");

    return 0;
}
