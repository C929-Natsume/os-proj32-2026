#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#define TRACE_PIPE_PATH "/sys/kernel/debug/tracing/trace_pipe"

static volatile int running = 1;

void signal_handler(int sig)
{
    printf("\n[LOADER] Stopping trace logger...\n");
    running = 0;
}

int main(int argc, char **argv)
{
    // 注意：不再加载 BPF，仅用于查看 bpf_printk 的输出
    printf("[LOADER] eBPF Trace Pipe Logger starting... (BPF attach is now handled by ringbuf_handler)\n");
    
    FILE *trace_file = fopen(TRACE_PIPE_PATH, "r");
    if (!trace_file) {
        fprintf(stderr, "[LOADER] Failed to open trace_pipe. Are you root?\n");
        return 1;
    }

    signal(SIGINT, signal_handler);

    char *line = NULL;
    size_t len = 0;

    while (running) {
        if (getline(&line, &len, trace_file) != -1) {
            // 过滤只打印带 [BPF] 标签的日志
            if (strstr(line, "[BPF]") != NULL) {
                printf("%s", line);
            }
        } else {
            usleep(100000); 
        }
    }

    if (line) free(line);
    fclose(trace_file);
    return 0;
}