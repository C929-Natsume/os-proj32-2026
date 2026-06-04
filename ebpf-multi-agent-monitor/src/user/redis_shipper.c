#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <hiredis/hiredis.h>
#include <stdint.h>
#include "../bpf/common.h"

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_CHANNEL "ebpf_events"

static redisContext *redis_ctx = NULL;

// Base64 编码函数
static void base64_encode(const unsigned char *src, size_t len, char *out) {
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, j = 0;
    for (i = 0; i < len; i += 3) {
        uint32_t n = (src[i] << 16) | ((i + 1 < len ? src[i + 1] : 0) << 8) | (i + 2 < len ? src[i + 2] : 0);
        out[j++] = b64chars[(n >> 18) & 0x3F];
        out[j++] = b64chars[(n >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64chars[(n >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? b64chars[n & 0x3F] : '=';
    }
    out[j] = '\0';
}

// 初始化 Redis 连接
int redis_shipper_init(void) {
    printf("[REDIS] Connecting to Redis at %s:%d...\n", REDIS_HOST, REDIS_PORT);
    redis_ctx = redisConnect(REDIS_HOST, REDIS_PORT);
    if (redis_ctx == NULL || redis_ctx->err) {
        if (redis_ctx) {
            fprintf(stderr, "[REDIS] Error: %s\n", redis_ctx->errstr);
            redisFree(redis_ctx);
        } else {
            fprintf(stderr, "[REDIS] Failed to allocate redis context\n");
        }
        return -1;
    }
    printf("[REDIS] Connected to Redis successfully\n");
    return 0;
}

// 关闭 Redis 连接
void redis_shipper_close(void) {
    if (redis_ctx) {
        printf("[REDIS] Closing Redis connection...\n");
        redisFree(redis_ctx);
        redis_ctx = NULL;
    }
}

// 发送系统事件
int ship_sys_event(struct sys_event *event) {
    if (!redis_ctx) return -1;
    char value[1024];
    
    if (event->event_type == EVENT_CONNECT) {
        snprintf(value, sizeof(value),
                 "{\"type\":%u,\"pid\":%u,\"child_pid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"dip\":\"%s\",\"dport\":%d}",
                 event->event_type, event->pid, event->child_pid, event->uid, event->timestamp, 
                 event->comm, event->connect.dip, event->connect.dport);
    } else {
        snprintf(value, sizeof(value),
                 "{\"type\":%u,\"pid\":%u,\"child_pid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"filename\":\"%s\"}",
                 event->event_type, event->pid, event->child_pid, event->uid, event->timestamp, 
                 event->comm, event->filename);
    }

    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    if (reply) freeReplyObject(reply);
    return 0;
}

// SSL
int ship_ssl_event(struct probe_SSL_data_t *event) {
    if (!redis_ctx) return -1;
    
    // 过滤条件：数据为空、拷贝失败、或者是纯握手包，直接丢弃
    if (event->buf_size == 0 || event->buf_filled == 0 || event->is_handshake || event->rw == 2) {
        return 0; 
    }

    uint32_t mapped_event_type = (event->rw == 0) ? EVENT_SSL_READ : EVENT_SSL_WRITE;

    // 动态分配 Base64 编码空间 (最大可达 21KB+)
    size_t b64_len = 4 * ((event->buf_size + 2) / 3) + 1;
    char *b64_data = malloc(b64_len);
    if (!b64_data) return -1;

    base64_encode((const unsigned char *)event->buf, event->buf_size, b64_data);

    // 动态分配 JSON 字符串空间 (防止 16KB 数据引发栈溢出)
    size_t json_buffer_size = b64_len + 1024; // 留出 1024 字节给 JSON 的其他字段
    char *value = malloc(json_buffer_size);
    if (!value) {
        free(b64_data);
        return -1;
    }

    // 打包为 JSON
    snprintf(value, json_buffer_size,
             "{\"type\":%u,\"pid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"data_len\":%u,\"data\":\"%s\"}",
             mapped_event_type, event->pid, event->timestamp_ns, event->comm, event->buf_size, b64_data);

    // 推送至 Redis
    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    if (reply == NULL) {
        printf("[REDIS ERROR] SSL push failed: %s\n", redis_ctx->errstr);
    } else {
        freeReplyObject(reply);
    }

    // 释放动态内存
    free(value);
    free(b64_data);
    
    return 0;
}