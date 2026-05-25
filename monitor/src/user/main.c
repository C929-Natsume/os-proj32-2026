#include <stdio.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include "proc.skel.h"
#include "fs.skel.h"
#include "net.skel.h"
#include "ssl.skel.h"
#include "proc_tree.h"
#include "common.h"

extern int handle_proc_event(void *ctx, void *data, size_t data_sz);
extern int handle_fs_event(void *ctx, void *data, size_t data_sz);
extern int handle_net_event(void *ctx, void *data, size_t data_sz);
extern int handle_ssl_event(void *ctx, void *data, size_t data_sz);
extern int open_log_file(const char *filename);
extern void close_log_file(void);

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -l, --log           Enable logging to file\n");
    printf("  -f, --file <name>   Log file name (default: %s)\n", LOG_FILE);
    printf("  -s, --ssl           Enable SSL monitoring (uprobes)\n");
    printf("  -h, --help          Show this help message\n");
}

int main(int argc, char **argv)
{
    struct proc_bpf *proc_skel = NULL;
    struct fs_bpf *fs_skel = NULL;
    struct net_bpf *net_skel = NULL;
    struct ssl_bpf *ssl_skel = NULL;
    struct ring_buffer *rb_proc = NULL, *rb_fs = NULL, *rb_net = NULL, *rb_ssl = NULL;
    int err = 0;
    const char *log_filename = LOG_FILE;
    int enable_ssl = 0;

    static struct option long_options[] = {
        {"log", no_argument, 0, 'l'},
        {"file", required_argument, 0, 'f'},
        {"ssl", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "lf:sh", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'l':
            enable_log = 1;
            break;
        case 'f':
            log_filename = optarg;
            break;
        case 's':
            enable_ssl = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (enable_log)
    {
        if (open_log_file(log_filename) != 0)
            return 1;
        printf("Logging enabled. Log file: %s\n", log_filename);
    }

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

    if (enable_ssl)
    {
        ssl_skel = ssl_bpf__open();
        if (!ssl_skel)
        {
            fprintf(stderr, "Failed to open ssl BPF\n");
            goto cleanup;
        }
        if (ssl_bpf__load(ssl_skel))
        {
            fprintf(stderr, "Failed to load ssl\n");
            goto cleanup;
        }
    }

    if (proc_bpf__attach(proc_skel) || fs_bpf__attach(fs_skel) || net_bpf__attach(net_skel))
    {
        fprintf(stderr, "Failed to attach\n");
        goto cleanup;
    }

    if (enable_ssl && ssl_bpf__attach(ssl_skel))
    {
        fprintf(stderr, "Failed to attach ssl\n");
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

    if (enable_ssl)
    {
        rb_ssl = ring_buffer__new(bpf_map__fd(ssl_skel->maps.ssl_events), handle_ssl_event, NULL, NULL);
        if (!rb_ssl)
        {
            err = -1;
            goto cleanup;
        }
    }

    scan_proc_directory();

    printf("Monitoring started");
    if (enable_ssl)
        printf(" (with SSL monitoring)");
    printf(". Press Ctrl+C to stop.\n");
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

        if (enable_ssl && rb_ssl)
        {
            err = ring_buffer__poll(rb_ssl, 100);
            if (err == -EINTR)
                break;
            if (err < 0)
            {
                fprintf(stderr, "Error polling ssl ring buffer: %d\n", err);
                break;
            }
        }
    }

    print_claude_tree();

cleanup:
    ring_buffer__free(rb_proc);
    ring_buffer__free(rb_fs);
    ring_buffer__free(rb_net);
    ring_buffer__free(rb_ssl);
    proc_bpf__destroy(proc_skel);
    fs_bpf__destroy(fs_skel);
    net_bpf__destroy(net_skel);
    ssl_bpf__destroy(ssl_skel);
    close_log_file();
    return err < 0 ? -err : 0;
}