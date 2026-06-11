#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf.h"
#include "../bpf/common.h"

// 声明来自 redis_shipper.c 的外部函数
extern int redis_shipper_init(void);
extern void redis_shipper_close(void);
extern int ship_sys_event(struct sys_event *event);
extern int ship_ssl_event(struct ssl_event *event);

#define SYS_RB_PIN_PATH "/sys/fs/bpf/sys_rb"
#define SSL_RB_PIN_PATH "/sys/fs/bpf/ssl_rb"

static volatile int running = 1;

void signal_handler(int sig)
{
    printf("\n[RINGBUF] Received signal %d, stopping...\n", sig);
    running = 0;
}

// ================= 处理系统调用的回调函数 =================
static int handle_sys_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len != sizeof(struct sys_event)) return 1;

    struct sys_event *event = data;
    printf("[RINGBUF] Received sys_event: type=%u, pid=%u, comm=%s\n",
           event->event_type, event->pid, event->comm);
    
    ship_sys_event(event);
    return 0;
}

// ================= 处理 SSL 明文的回调函数 =================
static int handle_ssl_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len != sizeof(struct ssl_event)) return 1;

    struct ssl_event *event = data;

    printf("\n================ SSL EVENT INTERCEPTED ================\n");
    printf("[RINGBUF] Type: %s | PID: %u | Comm: %s | Len: %u bytes\n",
           (event->event_type == EVENT_SSL_READ) ? "SSL_READ" : "SSL_WRITE",
           event->pid, event->comm, event->data_len);
           
    printf("[RINGBUF] Plaintext Data Preview:\n%s\n", event->data);
    printf("=======================================================\n");

    // 【新增】真正将 SSL 数据推送到 Redis
    ship_ssl_event(event);

    return 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    // 1. 初始化 Redis 管道
    if (redis_shipper_init() != 0) {
        fprintf(stderr, "[RINGBUF] Failed to init Redis shipper\n");
        return 1;
    }

    // 2. 获取被 Loader 钉固在文件系统中的 Map FD
    int sys_fd = bpf_obj_get(SYS_RB_PIN_PATH);
    if (sys_fd < 0) {
        fprintf(stderr, "[RINGBUF] Failed to get sys_rb FD. Is loader running?\n");
        redis_shipper_close();
        return 1;
    }

    int ssl_fd = bpf_obj_get(SSL_RB_PIN_PATH);
    if (ssl_fd < 0) {
        fprintf(stderr, "[RINGBUF] Failed to get ssl_rb FD. Is loader running?\n");
        close(sys_fd);
        redis_shipper_close();
        return 1;
    }

    // 3. 建立并合并 Ring Buffer 轮询
    struct ring_buffer *rb = ring_buffer__new(sys_fd, handle_sys_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        close(sys_fd);
        close(ssl_fd);
        return 1;
    }

    ring_buffer__add(rb, ssl_fd, handle_ssl_event, NULL);

    printf("[RINGBUF] Polling for System and SSL events... (Press Ctrl+C to stop)\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 4. 高性能单线程轮询
    while (running) {
        ring_buffer__poll(rb, 200); // 200ms 超时轮询
    }

    // 5. 清理资源
    printf("\n[RINGBUF] Cleaning up resources...\n");
    ring_buffer__free(rb);
    
    // 注意：只关闭 FD，不用去 destroy skeleton
    close(sys_fd);
    close(ssl_fd);
    redis_shipper_close();

    return 0;
}
