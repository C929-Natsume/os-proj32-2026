#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/common.h"
#include <time.h>

#include "redis_client.h"
#include "metrics_aggregator.h"

#define RES_MAP_PIN_PATH "/sys/fs/bpf/res_map"

#define SYS_RB_PIN_PATH "/sys/fs/bpf/sys_rb"
#define SSL_RB_PIN_PATH "/sys/fs/bpf/ssl_rb"
#define RAW_RB_PIN_PATH "/sys/fs/bpf/raw_rb"

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
    if (event->buf_size == 0 || event->buf_filled == 0) {
        printf("[RINGBUF-META] PID:%u (%s) | %s | Len:%u bytes (Payload Dropped)\n",
               event->pid, event->comm, (event->rw == 0) ? "RECV" : "SEND", event->len);
        
        ship_ssl_event(event); 
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

// ================= 处理纯文本协议数据事件 (stdio + 非SSL TCP) =================
static int handle_raw_event(void *ctx, void *data, size_t len) {
    if (len != sizeof(struct raw_data_event)) return 1;

    struct raw_data_event *event = data;

    // 丢弃空数据包 (sendmsg/recvmsg 元数据事件不丢弃)
    if (event->buf_filled == 0 && event->buf_size == 0) {
        // 元数据事件仍然推送 (记录通信行为)
        const char *dir_str = (event->direction == 0) ? "RECV" : "SEND";
        const char *src_str = (event->source == RAW_SRC_STDIO) ? "STDIO" : "TCP";
        printf("[RINGBUF] 纯文本协议事件 (元数据) -> %s/%s | PID:%u | FD:%u | Comm:%s\n",
               src_str, dir_str, event->pid, event->fd, event->comm);
        ship_raw_event(event);
        return 0;
    }

    const char *dir_str = (event->direction == 0) ? "READ" : "WRITE";
    const char *src_str = (event->source == RAW_SRC_STDIO) ? "STDIO" : "TCP";
    printf("\n============= RAW PROTOCOL EVENT ==============\n");
    printf("[RINGBUF] Source:%s | Dir:%s | PID:%u | FD:%u | Len:%u bytes\n",
           src_str, dir_str, event->pid, event->fd, event->buf_size);

    int preview_len = (event->buf_size > 512) ? 512 : event->buf_size;
    printf("[RINGBUF] Data Preview:\n%.*s\n", preview_len, event->buf);
    if (event->buf_size > 512) {
        printf("... [内容已折叠，完整 Payload 已推送至 Redis]\n");
    }
    printf("================================================\n");

    ship_raw_event(event);
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
    int raw_fd = -1;

    // 持续等待 Loader 主控引擎建立 BPF 管道 (Map Pinning)
    printf("[RINGBUF] 正在等待 Loader 主控引擎建立 BPF 管道 (Map Pinning)...\n");
    while (running) {
        if (sys_fd < 0) sys_fd = bpf_obj_get(SYS_RB_PIN_PATH);
        if (ssl_fd < 0) ssl_fd = bpf_obj_get(SSL_RB_PIN_PATH);
        if (raw_fd < 0) raw_fd = bpf_obj_get(RAW_RB_PIN_PATH);

        if (sys_fd >= 0 && ssl_fd >= 0 && raw_fd >= 0) {
            break; // 三个管道都建好了
        }
        usleep(500000); // 每 0.5 秒检测一次
    }

    if (!running) goto cleanup;

    printf("[RINGBUF] 成功连接三引擎数据管道！开始静默搬运数据...\n");

    // 用 sys_fd 创建 RingBuffer 轮询器
    struct ring_buffer *rb = ring_buffer__new(sys_fd, handle_sys_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] 创建系统行为 RingBuffer 失败\n");
        goto cleanup;
    }

    // 将 ssl_fd 缝合进同一个轮询器中
    if (ring_buffer__add(rb, ssl_fd, handle_ssl_event, NULL) != 0) {
        fprintf(stderr, "[-] 缝合 SSL RingBuffer 失败\n");
        ring_buffer__free(rb);
        goto cleanup;
    }

    // 将 raw_fd 缝合进同一个轮询器中
    if (ring_buffer__add(rb, raw_fd, handle_raw_event, NULL) != 0) {
        fprintf(stderr, "[-] 缝合 Raw Protocol RingBuffer 失败\n");
        ring_buffer__free(rb);
        goto cleanup;
    }

    // 单线程无锁轮询
    int res_fd = -1;
    time_t last_res_fetch = time(NULL);

    while (running) {
        // 每 2s 计算一次四维聚合数据
        if (res_fd < 0) {
            res_fd = bpf_obj_get(RES_MAP_PIN_PATH);
        }
        
        if (res_fd >= 0) {
            time_t now = time(NULL);
            if (now - last_res_fetch >= 2) {
                last_res_fetch = now;
                fetch_and_ship_resources(res_fd);
            }
        }

        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break; 
        if (err < 0) {
            fprintf(stderr, "[-] 轮询出错: %d\n", err);
            break;
        }
    }

    // 清理缓冲区对象
    ring_buffer__free(rb);

cleanup:
    // 关闭文件描述符 (仅仅是断开连接，不会销毁内核态的数据)
    if (res_fd >= 0) close(res_fd);
    if (sys_fd >= 0) close(sys_fd);
    if (ssl_fd >= 0) close(ssl_fd);
    if (raw_fd >= 0) close(raw_fd);
    redis_shipper_close();
    printf("[RINGBUF] 管道资源清理完毕，已安全退出。\n");

    return 0;
}