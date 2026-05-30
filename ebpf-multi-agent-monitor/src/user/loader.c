#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "sys_behavior.skel.h"
#include "ssl_sniffer.skel.h"

// 定义日志文件路径和内核 Trace Pipe 路径
#define LOG_FILE_PATH "../../logs/ebpf_log/test.log"
#define TRACE_PIPE_PATH "/sys/kernel/debug/tracing/trace_pipe"

static volatile int running = 1;

void signal_handler(int sig)
{
    printf("\n[LOADER] Received signal %d, shutting down...\n", sig);
    running = 0;
}

int main(int argc, char **argv)
{
    int enable_file_logging = 0;

    // ==========================================================
    // 解析命令行参数，检查是否包含 "--log"
    // ==========================================================
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--log") == 0) {
            enable_file_logging = 1;
            break;
        }
    }

    printf("[LOADER] eBPF Multi-Agent Monitor Loader starting...\n");

    printf("[LOADER] Step 1: Loading sys_behavior BPF skeleton...\n");
    struct sys_behavior_bpf_bpf *sys_skel = sys_behavior_bpf_bpf__open_and_load();
    if (!sys_skel) {
        fprintf(stderr, "[LOADER] Failed to load sys_behavior BPF program\n");
        return 1;
    }
    printf("[LOADER] Step 2: Attaching sys_behavior probes...\n");
    int err = sys_behavior_bpf_bpf__attach(sys_skel);
    if (err) {
        fprintf(stderr, "[LOADER] Failed to attach sys_behavior BPF program\n");
        return 1;
    }
    printf("[LOADER] sys_behavior BPF program attached successfully\n");

    printf("[LOADER] Step 3: Loading ssl_sniffer BPF skeleton...\n");
    struct ssl_sniffer_bpf_bpf *ssl_skel = ssl_sniffer_bpf_bpf__open_and_load();
    if (!ssl_skel) {
        fprintf(stderr, "[LOADER] Failed to load ssl_sniffer BPF program\n");
        return 1;
    }
    printf("[LOADER] Step 4: Attaching ssl_sniffer probes...\n");
    err = ssl_sniffer_bpf_bpf__attach(ssl_skel);
    if (err) {
        fprintf(stderr, "[LOADER] Failed to attach ssl_sniffer BPF program\n");
        return 1;
    }
    printf("[LOADER] ssl_sniffer BPF program attached successfully\n");

    printf("[LOADER] All BPF programs loaded and attached successfully\n");
    printf("[LOADER] eBPF kernel probes are now monitoring system calls and SSL traffic\n");

    // ==========================================================
    // 修改逻辑：只有在开启 logging 时才打开文件和管道
    // ==========================================================
    FILE *out_stream = NULL;
    FILE *trace_file = NULL;

    if (enable_file_logging) {
        out_stream = fopen(LOG_FILE_PATH, "a"); // 以追加模式打开日志文件
        if (!out_stream) {
            perror("[LOADER] Failed to open target log file");
            fprintf(stderr, "Hint: Make sure the directory logs/ebpf_log/ exists!\n");
            return 1;
        }
        
        trace_file = fopen(TRACE_PIPE_PATH, "r"); // 以只读模式打开内核管道
        if (!trace_file) {
            perror("[LOADER] Failed to open trace_pipe");
            fclose(out_stream);
            return 1;
        }
        printf("[LOADER] Now writing eBPF logs to: %s\n", LOG_FILE_PATH);
    } else {
        printf("[LOADER] Logging disabled. Running silently in the background.\n");
        printf("[LOADER] Hint: Use 'sudo ./loader --log' to capture logs to file.\n");
    }

    printf("[LOADER] Waiting for events... (Press Ctrl+C to stop)\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    char *line = NULL;
    size_t len = 0;
    ssize_t read_bytes;

    // ==========================================================
    // 主循环：依据是否开启日志执行不同策略
    // ==========================================================
    while (running) {
        if (enable_file_logging) {
            // 策略 A：阻塞式读取 trace_pipe，并将日志写入文件
            read_bytes = getline(&line, &len, trace_file);
            
            if (read_bytes != -1) {
                if (strstr(line, "[BPF]") != NULL) {
                    fprintf(out_stream, "%s", line);
                    fflush(out_stream); 
                }
            } else {
                if (errno != EINTR) {
                    usleep(100000); 
                }
            }
        } else {
            // 策略 B：没有开启日志时，使用 pause() 将当前进程挂起
            // 这完全不消耗 CPU，直到用户按下 Ctrl+C (触发 SIGINT 信号) 才会唤醒
            pause(); 
        }
    }

    // ==========================================================
    // 清理资源
    // ==========================================================
    printf("[LOADER] Cleaning up resources...\n");
    if (line) free(line);
    
    // 安全地关闭可能打开的文件描述符
    if (trace_file) fclose(trace_file);
    if (out_stream) fclose(out_stream);

    sys_behavior_bpf_bpf__destroy(sys_skel);
    ssl_sniffer_bpf_bpf__destroy(ssl_skel);
    
    printf("[LOADER] Shutdown complete.\n");
    return 0;
}