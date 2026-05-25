#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "sys_behavior.skel.h"
#include "ssl_sniffer.skel.h"

static volatile int running = 1;

void signal_handler(int sig)
{
    printf("[LOADER] Received signal %d, shutting down...\n", sig);
    running = 0;
}

int main(int argc, char **argv)
{
    printf("[LOADER] eBPF Multi-Agent Monitor Loader starting...\n");

    printf("[LOADER] Step 1: Loading sys_behavior BPF skeleton...\n");
    struct sys_behavior_bpf *sys_skel = sys_behavior_bpf__open_and_load();
    if (!sys_skel) {
        fprintf(stderr, "[LOADER] Failed to load sys_behavior BPF program\n");
        return 1;
    }
    printf("[LOADER] Step 2: Attaching sys_behavior probes...\n");
    int err = sys_behavior_bpf__attach(sys_skel);
    if (err) {
        fprintf(stderr, "[LOADER] Failed to attach sys_behavior BPF program\n");
        return 1;
    }
    printf("[LOADER] sys_behavior BPF program attached successfully\n");

    printf("[LOADER] Step 3: Loading ssl_sniffer BPF skeleton...\n");
    struct ssl_sniffer_bpf *ssl_skel = ssl_sniffer_bpf__open_and_load();
    if (!ssl_skel) {
        fprintf(stderr, "[LOADER] Failed to load ssl_sniffer BPF program\n");
        return 1;
    }
    printf("[LOADER] Step 4: Attaching ssl_sniffer probes...\n");
    err = ssl_sniffer_bpf__attach(ssl_skel);
    if (err) {
        fprintf(stderr, "[LOADER] Failed to attach ssl_sniffer BPF program\n");
        return 1;
    }
    printf("[LOADER] ssl_sniffer BPF program attached successfully\n");

    printf("[LOADER] All BPF programs loaded and attached successfully\n");
    printf("[LOADER] eBPF kernel probes are now monitoring system calls and SSL traffic\n");
    printf("[LOADER] Waiting for events... (Press Ctrl+C to stop)\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while (running) {
        printf("[LOADER] BPF loader running, monitoring active...\n");
        sleep(10);
    }

    printf("[LOADER] Cleaning up BPF programs...\n");
    sys_behavior_bpf__destroy(sys_skel);
    ssl_sniffer_bpf__destroy(ssl_skel);
    printf("[LOADER] Loader shutdown complete\n");

    return 0;
}
