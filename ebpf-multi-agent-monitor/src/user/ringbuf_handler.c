#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/common.h"

// 外部 Redis 数据推送接口
extern int redis_shipper_init(void);
extern void redis_shipper_close(void);
extern int ship_sys_event(struct sys_event *event);
extern int ship_ssl_event(struct probe_SSL_data_t *event);

#define SYS_RB_PIN_PATH "/sys/fs/bpf/sys_rb"
#define SSL_RB_PIN_PATH "/sys/fs/bpf/ssl_rb"

static volatile int running = 1;

void signal_handler(int sig) {
    printf("\n[RINGBUF] 收到终止信号 %d，正在安全停止搬运管道...\n", sig);
    running = 0;
}

// ================= 处理系统调用事件 =================
static int handle_sys_event(void *ctx, void *data, size_t len) {
    if (len != sizeof(struct sys_event)) return 1;

    struct sys_event *event = data;
    // 打印带有 child_pid 的系统日志，方便核对血缘树
    printf("[RINGBUF] 系统行为 -> Type:%u | PID:%u | ChildPID:%u | Comm:%s\n",
           event->event_type, event->pid, event->child_pid, event->comm);
    
    ship_sys_event(event);
    return 0;
}

// ================= 处理 SSL 加密流量事件 =================
static int handle_ssl_event(void *ctx, void *data, size_t len) {
    if (len != sizeof(struct probe_SSL_data_t)) return 1;

    struct probe_SSL_data_t *event = data;

    // 过滤：丢弃空包、拷贝失败的包、纯握手包、未知的底层通讯
    if (event->buf_size == 0 || event->buf_filled == 0 || event->is_handshake || event->rw == 2) {
        return 0; 
    }

    printf("\n================ SSL EVENT INTERCEPTED ================\n");
    printf("[RINGBUF] Type: %s | PID: %u | TID: %u | Engine: %d | Len: %u bytes\n",
           (event->rw == 0) ? "READ(Response)" : "WRITE(Prompt)",
           event->pid, event->tid, event->engine, event->buf_size);
           
    // 对于极长的上下文只打印前 1024 字节作为终端预览
    int preview_len = (event->buf_size > 1024) ? 1024 : event->buf_size;
    printf("[RINGBUF] Plaintext Data Preview:\n%.*s\n", preview_len, event->buf);
    
    if (event->buf_size > 1024) {
        printf("... [内容过长已折叠，完整 16KB Payload 已推送至 Redis]\n");
    }
    printf("=======================================================\n");

    ship_ssl_event(event);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("=======================================================\n");
    printf("[RINGBUF] eBPF 统一数据搬运总线启动...\n");
    printf("=======================================================\n");

    if (redis_shipper_init() != 0) {
        fprintf(stderr, "[-] Redis 管道初始化失败！\n");
        return 1;
    }

    int sys_fd = -1;
    int ssl_fd = -1;

    // 持续等待 Loader 把 Map 钉固到文件系统
    printf("[RINGBUF] 正在等待 Loader 主控引擎建立 BPF 管道 (Map Pinning)...\n");
    while (running) {
        if (sys_fd < 0) sys_fd = bpf_obj_get(SYS_RB_PIN_PATH);
        if (ssl_fd < 0) ssl_fd = bpf_obj_get(SSL_RB_PIN_PATH);
        
        if (sys_fd >= 0 && ssl_fd >= 0) {
            break; // 两个管道都建好了，跳出等待
        }
        usleep(500000); // 没建好就每 0.5 秒检测一次，不消耗 CPU
    }

    if (!running) goto cleanup;

    printf("[RINGBUF] 成功连接双引擎数据管道！开始静默搬运数据...\n");

    // 1. 先用 sys_fd 创建 RingBuffer 轮询器
    struct ring_buffer *rb = ring_buffer__new(sys_fd, handle_sys_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] 创建系统行为 RingBuffer 失败\n");
        goto cleanup;
    }

    // 2. 将 ssl_fd 缝合进同一个轮询器中（eBPF 支持单个用户态程序合并监听多个 Map）
    if (ring_buffer__add(rb, ssl_fd, handle_ssl_event, NULL) != 0) {
        fprintf(stderr, "[-] 缝合 SSL RingBuffer 失败\n");
        ring_buffer__free(rb);
        goto cleanup;
    }

    // 3. 高性能单线程无锁轮询
    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break; // 被 Ctrl+C 打断
        if (err < 0) {
            fprintf(stderr, "[-] 轮询出错: %d\n", err);
            break;
        }
    }

    // 清理缓冲区对象
    ring_buffer__free(rb);

cleanup:
    // 关闭文件描述符 (仅仅是断开连接，不会销毁内核态的数据)
    if (sys_fd >= 0) close(sys_fd);
    if (ssl_fd >= 0) close(ssl_fd);
    redis_shipper_close();
    printf("[RINGBUF] 管道资源清理完毕，已安全退出。\n");

    return 0;
}