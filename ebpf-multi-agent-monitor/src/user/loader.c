#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sys_behavior.skel.h"
#include "ssl_sniffer.skel.h"

#define TRACE_PIPE_PATH "/sys/kernel/debug/tracing/trace_pipe"

// 定义 BPF Map 钉固的路径
#define SYS_RB_PIN_PATH "/sys/fs/bpf/sys_rb"
#define SSL_RB_PIN_PATH "/sys/fs/bpf/ssl_rb"

static volatile int running = 1;

void signal_handler(int sig)
{
    printf("\n[LOADER] Stopping trace logger and cleaning up BPF...\n");
    running = 0;
}

int main(int argc, char **argv)
{
    printf("[LOADER] eBPF Loader starting... (Handling BPF attach and Map pinning)\n");

    // 1. 加载并挂载系统行为 BPF 骨架
    struct sys_behavior_bpf_bpf *sys_skel = sys_behavior_bpf_bpf__open_and_load();
    if (!sys_skel) {
        fprintf(stderr, "[LOADER] Failed to load sys_behavior\n");
        return 1;
    }
    sys_behavior_bpf_bpf__attach(sys_skel);

    // 2. 加载并挂载 SSL 嗅探 BPF 骨架
    struct ssl_sniffer_bpf_bpf *ssl_skel = ssl_sniffer_bpf_bpf__open_and_load();
    if (!ssl_skel) {
        fprintf(stderr, "[LOADER] Failed to load ssl_sniffer\n");
        sys_behavior_bpf_bpf__destroy(sys_skel);
        return 1;
    }
    ssl_sniffer_bpf_bpf__attach(ssl_skel);

    // 3. 将 RingBuffer Map 钉固 (Pin) 到文件系统，供 ringbuf_handler 读取
    // 钉固前先尝试解绑，防止上次异常退出导致残留
    bpf_map__unpin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
    bpf_map__unpin(ssl_skel->maps.ssl_rb, SSL_RB_PIN_PATH);

    if (bpf_map__pin(sys_skel->maps.rb, SYS_RB_PIN_PATH) != 0 || 
        bpf_map__pin(ssl_skel->maps.ssl_rb, SSL_RB_PIN_PATH) != 0) {
        fprintf(stderr, "[LOADER] Failed to pin maps to /sys/fs/bpf/\n");
        // 如果钉固失败也做一下清理
        sys_behavior_bpf_bpf__destroy(sys_skel);
        ssl_sniffer_bpf_bpf__destroy(ssl_skel);
        return 1;
    }
    printf("[LOADER] BPF programs attached and Maps pinned successfully.\n");
    
    // 4. 原有的 trace_pipe 监听逻辑
    FILE *trace_file = fopen(TRACE_PIPE_PATH, "r");
    if (!trace_file) {
        fprintf(stderr, "[LOADER] Failed to open trace_pipe. Are you root?\n");
        running = 0;
    }

    // 使用 sigaction 替代老式 signal，避免 getline 被自动重启
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // 核心：设为 0，坚决不用 SA_RESTART

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to set SIGINT handler");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Failed to set SIGTERM handler");
    }

    char *line = NULL;
    size_t len = 0;

    while (running) {
        if (trace_file && getline(&line, &len, trace_file) != -1) {
            // 过滤只打印带 [BPF] 标签的日志
            if (strstr(line, "[BPF]") != NULL) {
                printf("%s", line);
            }
        } else {
            usleep(100000); 
        }
    }

    // 5. 退出时清理资源和钉固文件
    if (line) free(line);
    if (trace_file) fclose(trace_file);

    bpf_map__unpin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
    bpf_map__unpin(ssl_skel->maps.ssl_rb, SSL_RB_PIN_PATH);
    sys_behavior_bpf_bpf__destroy(sys_skel);
    ssl_sniffer_bpf_bpf__destroy(ssl_skel);
    printf("[LOADER] Exited cleanly.\n");

    return 0;
}