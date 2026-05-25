#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <hiredis/hiredis.h>
#include "common.h"

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_CHANNEL "ebpf_events"

static redisContext *redis_ctx = NULL;

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

void redis_shipper_close(void)
{
    if (redis_ctx) {
        printf("[REDIS] Closing Redis connection...\n");
        redisFree(redis_ctx);
        redis_ctx = NULL;
    }
}

int ship_sys_event(struct sys_event *event)
{
    if (!redis_ctx) {
        fprintf(stderr, "[REDIS] Not connected to Redis\n");
        return -1;
    }

    char key[64];
    snprintf(key, sizeof(key), "sys_event:%u:%llu", event->pid, event->timestamp);

    char value[4096];
    int len = snprintf(value, sizeof(value),
                       "{\"type\":%u,\"pid\":%u,\"uid\":%u,\"comm\":\"%s\",\"filename\":\"%s\"}",
                       event->event_type, event->pid, event->uid, event->comm, event->filename);

    redisReply *reply = redisCommand(redis_ctx, "SET %s %b", key, value, len);
    if (reply == NULL) {
        fprintf(stderr, "[REDIS] Error shipping sys_event\n");
        return -1;
    }
    printf("[REDIS] Shipped sys_event: key=%s\n", key);
    freeReplyObject(reply);

    reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    if (reply) {
        printf("[REDIS] Published sys_event to channel %s\n", REDIS_CHANNEL);
        freeReplyObject(reply);
    }

    return 0;
}

int ship_ssl_event(struct ssl_event *event)
{
    if (!redis_ctx) {
        fprintf(stderr, "[REDIS] Not connected to Redis\n");
        return -1;
    }

    char key[64];
    snprintf(key, sizeof(key), "ssl_event:%u:%llu", event->pid, event->timestamp);

    char value[4096];
    int len = snprintf(value, sizeof(value),
                       "{\"type\":%u,\"pid\":%u,\"comm\":\"%s\",\"data_len\":%u}",
                       event->event_type, event->pid, event->comm, event->data_len);

    redisReply *reply = redisCommand(redis_ctx, "SET %s %b", key, value, len);
    if (reply == NULL) {
        fprintf(stderr, "[REDIS] Error shipping ssl_event\n");
        return -1;
    }
    printf("[REDIS] Shipped ssl_event: key=%s\n", key);
    freeReplyObject(reply);

    reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    if (reply) {
        printf("[REDIS] Published ssl_event to channel %s\n", REDIS_CHANNEL);
        freeReplyObject(reply);
    }

    return 0;
}

int main(int argc, char **argv)
{
    printf("[REDIS] Redis Shipper starting...\n");

    if (redis_shipper_init() != 0) {
        fprintf(stderr, "[REDIS] Failed to initialize Redis shipper\n");
        return 1;
    }

    printf("[REDIS] Redis shipper ready, waiting for events to ship...\n");
    printf("[REDIS] Events will be published to channel: %s\n", REDIS_CHANNEL);

    struct sys_event test_sys_event = {
        .event_type = EVENT_EXECVE,
        .pid = 1234,
        .uid = 1000,
        .timestamp = 1234567890,
        .comm = "test_proc",
        .filename = "/bin/ls"
    };
    printf("[REDIS] Sending test sys_event...\n");
    ship_sys_event(&test_sys_event);

    struct ssl_event test_ssl_event = {
        .event_type = EVENT_SSL_READ,
        .pid = 5678,
        .timestamp = 1234567891,
        .comm = "test_ssl",
        .data_len = 1024
    };
    printf("[REDIS] Sending test ssl_event...\n");
    ship_ssl_event(&test_ssl_event);

    printf("[REDIS] Test events shipped successfully\n");

    redis_shipper_close();
    printf("[REDIS] Redis shipper shutdown complete\n");

    return 0;
}
