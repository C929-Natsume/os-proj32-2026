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

// 新增 Base64 编码函数
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
int redis_shipper_init(void)
{
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
void redis_shipper_close(void)
{
    if (redis_ctx) {
        printf("[REDIS] Closing Redis connection...\n");
        redisFree(redis_ctx);
        redis_ctx = NULL;
    }
}

// 真正发送系统事件到 Redis
int ship_sys_event(struct sys_event *event)
{
    if (!redis_ctx) return -1;
    
    char value[1024];
    
    // 动态构建 JSON：区分网络事件和文件/进程事件
    if (event->event_type == EVENT_CONNECT) {
        // 网络事件：包含 dip (目标IP) 和 dport (目标端口)
        snprintf(value, sizeof(value),
                 "{\"type\":%u,\"pid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"dip\":\"%s\",\"dport\":%d}",
                 event->event_type, event->pid, event->uid, event->timestamp, 
                 event->comm, event->connect.dip, event->connect.dport);
    } else {
        // 文件/进程事件：包含 filename (文件路径)
        snprintf(value, sizeof(value),
                 "{\"type\":%u,\"pid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"filename\":\"%s\"}",
                 event->event_type, event->pid, event->uid, event->timestamp, 
                 event->comm, event->filename);
    }

    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    if (reply) freeReplyObject(reply);
    return 0;
}

// 发送 SSL 事件
int ship_ssl_event(struct ssl_event *event)
{
    if (!redis_ctx) return -1;
    
    // 如果数据长度为 0，直接跳过避免浪费资源
    if (event->data_len == 0) return 0;

    // 1. 计算 Base64 编码后的长度 (公式：4 * ceil(len / 3) + 1 用于 '\0')
    size_t b64_len = 4 * ((event->data_len + 2) / 3) + 1;
    
    // 2. 动态分配内存存放 Base64 字符串
    char *b64_data = malloc(b64_len);
    if (!b64_data) {
        fprintf(stderr, "[REDIS] Failed to allocate memory for Base64\n");
        return -1;
    }

    // 3. 将明文 payload 进行 Base64 编码
    base64_encode((const unsigned char *)event->data, event->data_len, b64_data);

    // 4. 构建包含 Base64 数据的 JSON (缓冲区开大到 8192 防止溢出)
    char value[8192];
    snprintf(value, sizeof(value),
             "{\"type\":%u,\"pid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"data_len\":%u,\"data\":\"%s\"}",
             event->event_type, event->pid, event->timestamp, event->comm, event->data_len, b64_data);

    // 5. 发布到 Redis (你当前使用的是 PUBLISH 模式)
    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    if (reply == NULL) {
        printf("[REDIS ERROR] SSL push failed: %s\n", redis_ctx->errstr);
    } else {
        freeReplyObject(reply);
    }

    // 6. 释放 Base64 内存，防止内存泄漏
    free(b64_data);
    
    return 0;
}