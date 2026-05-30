#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <hiredis/hiredis.h>
#include "../bpf/common.h"

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_CHANNEL "ebpf_events"

static redisContext *redis_ctx = NULL;

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

// (如果启用了 SSL 发送，同样需要带上 timestamp)
int ship_ssl_event(struct ssl_event *event)
{
    if (!redis_ctx) return -1;
    char value[4096];
    
    // 注意：如果是生产环境发送真实 payload，建议在这里对 event->data 做 Base64 编码，防止破坏 JSON 结构。
    snprintf(value, sizeof(value),
             "{\"type\":%u,\"pid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"data_len\":%u}",
             event->event_type, event->pid, event->timestamp, event->comm, event->data_len);

    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    if (reply) freeReplyObject(reply);
    return 0;
}