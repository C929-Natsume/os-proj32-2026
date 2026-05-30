#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "sys_behavior.skel.h"
#include "ssl_sniffer.skel.h"
#include "../bpf/common.h"

// 声明来自 redis_shipper.c 的外部函数
extern int redis_shipper_init(void);
extern void redis_shipper_close(void);
extern int ship_sys_event(struct sys_event *event);
extern int ship_ssl_event(struct ssl_event *event);

static volatile int running = 1;

void signal_handler(int sig)
{
    printf("\n[RINGBUF] Received signal %d, stopping...\n", sig);
    running = 0;
}

// ================= 处理系统调用的回调函数 =================
static int handle_sys_event(void *ctx, void *data, size_t len)
{
    if (len != sizeof(struct sys_event)) return 1;

    struct sys_event *event = data;
    printf("[RINGBUF] Received sys_event: type=%u, pid=%u, comm=%s\n",
           event->event_type, event->pid, event->comm);
    
    // 将系统行为数据实时推送给 Redis
    ship_sys_event(event);
    
    return 0;
}

// ================= 处理 SSL 明文的回调函数 =================
static int handle_ssl_event(void *ctx, void *data, size_t len)
{
    if (len != sizeof(struct ssl_event)) return 1;

    struct ssl_event *event = data;

    // 在终端高亮打印截获到的 SSL 流量
    printf("\n================ SSL EVENT INTERCEPTED ================\n");
    printf("[RINGBUF] Type: %s | PID: %u | Comm: %s | Len: %u bytes\n",
           (event->event_type == EVENT_SSL_READ) ? "SSL_READ" : "SSL_WRITE",
           event->pid, event->comm, event->data_len);
           
    // 打印从内核态传过来的明文内容
    printf("[RINGBUF] Plaintext Data Preview:\n%s\n", event->data);
    printf("=======================================================\n");

    /* * 注意：这里暂时不调用 ship_ssl_event(event) 推送到 Redis。
     * 因为 event->data 里现在是真实的 HTTP 请求头和 HTML 源码，包含大量回车和引号。
     * 如果直接按你之前在 redis_shipper.c 里的 snprintf 拼接成 JSON 发送，
     * 会导致 JSON 格式错乱并报错。建议后续在 Python 端处理或在 C 里做 Base64 编码后再推送。
     */
    
    return 0;
}

int main(int argc, char **argv)
{
    // 1. 初始化 Redis 管道
    if (redis_shipper_init() != 0) {
        fprintf(stderr, "[RINGBUF] Failed to init Redis shipper\n");
        return 1;
    }

    // 2. 加载并挂载系统行为 BPF 骨架
    printf("[RINGBUF] Loading sys_behavior BPF program...\n");
    struct sys_behavior_bpf_bpf *sys_skel = sys_behavior_bpf_bpf__open_and_load();
    if (!sys_skel) {
        fprintf(stderr, "Failed to load sys_behavior\n");
        return 1;
    }
    sys_behavior_bpf_bpf__attach(sys_skel);

    // 3. 加载并挂载 SSL 嗅探 BPF 骨架
    printf("[RINGBUF] Loading ssl_sniffer BPF program...\n");
    struct ssl_sniffer_bpf_bpf *ssl_skel = ssl_sniffer_bpf_bpf__open_and_load();
    if (!ssl_skel) {
        fprintf(stderr, "Failed to load ssl_sniffer\n");
        return 1;
    }
    ssl_sniffer_bpf_bpf__attach(ssl_skel);

    // 4. 合并开启 Ring Buffer 轮询 (将两个 map 绑定到同一个轮询器中)
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(sys_skel->maps.rb), handle_sys_event, NULL, NULL);
    
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    // 将 SSL 的 Ring Buffer 也添加进这个轮询器
    ring_buffer__add(rb, bpf_map__fd(ssl_skel->maps.ssl_rb), handle_ssl_event, NULL);

    printf("[RINGBUF] Polling for System and SSL events... (Press Ctrl+C to stop)\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 5. 高性能单线程轮询
    while (running) {
        ring_buffer__poll(rb, 200); // 200ms 超时轮询
    }

    // 6. 清理资源
    printf("\n[RINGBUF] Cleaning up resources...\n");
    ring_buffer__free(rb);
    sys_behavior_bpf_bpf__destroy(sys_skel);
    ssl_sniffer_bpf_bpf__destroy(ssl_skel);
    redis_shipper_close();

    return 0;
}