#include <stdio.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "proc.skel.h"
#include "fs.skel.h"
#include "net.skel.h"
#include "proc_tree.h"
#include "intra_analyzer.h"

extern int handle_proc_event(void *ctx, void *data, size_t data_sz);
extern int handle_fs_event(void *ctx, void *data, size_t data_sz);
extern int handle_net_event(void *ctx, void *data, size_t data_sz);

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

int main()
{
    struct proc_bpf *proc_skel = NULL;
    struct fs_bpf *fs_skel = NULL;
    struct net_bpf *net_skel = NULL;
    struct ring_buffer *rb_proc = NULL, *rb_fs = NULL, *rb_net = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    proc_skel = proc_bpf__open();
    if (!proc_skel)
    {
        fprintf(stderr, "Failed to open proc BPF\n");
        goto cleanup;
    }
    if (proc_bpf__load(proc_skel))
    {
        fprintf(stderr, "Failed to load proc\n");
        goto cleanup;
    }

    fs_skel = fs_bpf__open();
    if (!fs_skel)
    {
        fprintf(stderr, "Failed to open fs BPF\n");
        goto cleanup;
    }
    if (fs_bpf__load(fs_skel))
    {
        fprintf(stderr, "Failed to load fs\n");
        goto cleanup;
    }

    net_skel = net_bpf__open();
    if (!net_skel)
    {
        fprintf(stderr, "Failed to open net BPF\n");
        goto cleanup;
    }
    if (net_bpf__load(net_skel))
    {
        fprintf(stderr, "Failed to load net\n");
        goto cleanup;
    }

    if (proc_bpf__attach(proc_skel) || fs_bpf__attach(fs_skel) || net_bpf__attach(net_skel))
    {
        fprintf(stderr, "Failed to attach\n");
        goto cleanup;
    }

    rb_proc = ring_buffer__new(bpf_map__fd(proc_skel->maps.proc_events), handle_proc_event, NULL, NULL);
    rb_fs = ring_buffer__new(bpf_map__fd(fs_skel->maps.fs_events), handle_fs_event, NULL, NULL);
    rb_net = ring_buffer__new(bpf_map__fd(net_skel->maps.net_events), handle_net_event, NULL, NULL);
    if (!rb_proc || !rb_fs || !rb_net)
    {
        err = -1;
        goto cleanup;
    }

    // 启动前扫描 /proc 获取现有进程信息
    scan_proc_directory();
    intra_init();

    printf("Monitoring started. Press Ctrl+C to stop.\n");
    fflush(stdout);

    while (!exiting)
    {
        err = ring_buffer__poll(rb_proc, 100);
        if (err == -EINTR)
            break;
        if (err < 0)
        {
            fprintf(stderr, "Error polling proc ring buffer: %d\n", err);
            break;
        }

        err = ring_buffer__poll(rb_fs, 100);
        if (err == -EINTR)
            break;
        if (err < 0)
        {
            fprintf(stderr, "Error polling fs ring buffer: %d\n", err);
            break;
        }

        err = ring_buffer__poll(rb_net, 100);
        if (err == -EINTR)
            break;
        if (err < 0)
        {
            fprintf(stderr, "Error polling net ring buffer: %d\n", err);
            break;
        }
    }

    print_claude_tree();
    // print_all_tree();

cleanup:
    ring_buffer__free(rb_proc);
    ring_buffer__free(rb_fs);
    ring_buffer__free(rb_net);
    proc_bpf__destroy(proc_skel);
    fs_bpf__destroy(fs_skel);
    net_bpf__destroy(net_skel);
    return err < 0 ? -err : 0;
}
