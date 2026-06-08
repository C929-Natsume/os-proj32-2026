#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <hiredis/hiredis.h>
#include <stdint.h>
#include <time.h>
#include "../bpf/common.h"

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_CHANNEL_BEHAVIOR "ebpf_behavior_events"
#define REDIS_CHANNEL_RESOURCE "ebpf_resource_events"

static redisContext *redis_ctx = NULL;

static const char* get_behavior_name(uint32_t type) {
    switch(type) {
        case EVENT_EXECVE:   return "PROCESS_EXECUTE";      // 执行系统命令
        case EVENT_FORK:     return "PROCESS_FORK";         // 派生子进程
        case EVENT_OPEN:     return "FILE_OPEN";            // 打开/读取文件
        case EVENT_UNLINK:   return "FILE_DELETE";          // 删除文件
        case EVENT_CONNECT:  return "NETWORK_CONNECT";      // 建立网络连接
        case EVENT_SSL_READ: return "SSL_RECEIVE_RESPONSE"; // 接收大模型响应
        case EVENT_SSL_WRITE:return "SSL_SEND_PROMPT";      // 发送提示词请求
        case EVENT_CHMOD:    return "PERMISSION_CHANGE";    // 修改文件权限
        default:             return "UNKNOWN_BEHAVIOR";
    }
}

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

// 推送系统行为事件
int ship_sys_event(struct sys_event *event) {
    if (!redis_ctx) return -1;
    char value[2048]; // 扩大缓冲区以容纳完整的 JSON
    
    const char* behavior_name = get_behavior_name(event->event_type);

    if (event->event_type == EVENT_CONNECT) {
        // 网络底层连接事件
        snprintf(value, sizeof(value),
                 "{"
                 "\"agent_name\":\"%s\","
                 "\"agent_no\":%u,"
                 "\"behavior_name\":\"%s\","
                 "\"behavior_no\":%u,"
                 "\"timestamp\":%llu,"
                 "\"operation\":{\"pid\":%u, \"child_pid\":%u, \"comm\":\"%s\", \"dip\":\"%s\", \"dport\":%d}"
                 "}",
                 event->agent_name, event->agent_id, 
                 behavior_name, event->event_type, 
                 event->timestamp,
                 event->pid, event->child_pid, event->comm, 
                 event->connect.dip, event->connect.dport);
    } else {
        // 文件系统及进程操作事件
        snprintf(value, sizeof(value),
                 "{"
                 "\"agent_name\":\"%s\","
                 "\"agent_no\":%u,"
                 "\"behavior_name\":\"%s\","
                 "\"behavior_no\":%u,"
                 "\"timestamp\":%llu,"
                 "\"operation\":{\"pid\":%u, \"child_pid\":%u, \"comm\":\"%s\", \"target_file\":\"%s\"}"
                 "}",
                 event->agent_name, event->agent_id, 
                 behavior_name, event->event_type, 
                 event->timestamp,
                 event->pid, event->child_pid, event->comm, 
                 event->filename);
    }

    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL_BEHAVIOR, value);
    if (reply) freeReplyObject(reply);
    return 0;
}

// 推送网络应用层事件
int ship_ssl_event(struct probe_SSL_data_t *event) {
    if (!redis_ctx) return -1;
    
    // 过滤条件：数据为空、拷贝失败、或者是纯握手包，直接丢弃
    if (event->buf_size == 0 || event->buf_filled == 0 || event->is_handshake || event->rw == 2) {
        return 0; 
    }

    uint32_t mapped_event_type = (event->rw == 0) ? EVENT_SSL_READ : EVENT_SSL_WRITE;
    const char* behavior_name = get_behavior_name(mapped_event_type);

    // 动态分配 Base64 编码空间
    size_t b64_len = 4 * ((event->buf_size + 2) / 3) + 1;
    char *b64_data = malloc(b64_len);
    if (!b64_data) return -1;

    base64_encode((const unsigned char *)event->buf, event->buf_size, b64_data);

    // 动态分配 JSON 字符串空间
    size_t json_buffer_size = b64_len + 1024; 
    char *value = malloc(json_buffer_size);
    if (!value) {
        free(b64_data);
        return -1;
    }

    // 打包 JSON
    snprintf(value, json_buffer_size,
             "{"
             "\"agent_name\":\"%s\","
             "\"agent_no\":%u,"
             "\"behavior_name\":\"%s\","
             "\"behavior_no\":%u,"
             "\"timestamp\":%llu,"
             "\"operation\":{\"pid\":%u, \"tid\":%u, \"comm\":\"%s\", \"payload_bytes\":%u},"
             "\"network_payload\":\"%s\"" // 附加网络传输内容
             "}",
             event->agent_name, event->agent_id, 
             behavior_name, mapped_event_type, 
             event->timestamp_ns,
             event->pid, event->tid, event->comm, event->buf_size, 
             b64_data);

    // 推送至 Redis
    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL_BEHAVIOR, value);
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

// 从 Procfs 读取真实物理内存
static __u64 get_process_rss_bytes(__u32 pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%u/statm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0; 

    __u64 size, resident, shared, text, lib, data, dt;
    if (fscanf(f, "%llu %llu %llu %llu %llu %llu %llu", 
               &size, &resident, &shared, &text, &lib, &data, &dt) != 7) {
        fclose(f);
        return 0;
    }
    fclose(f);
    // Linux 默认页大小是 4096 字节
    return resident * 4096;
}

// 推送资源消耗事件
int ship_resource_sample(__u32 level, __u64 target_id, __u64 cpu_ns, __u64 rss_bytes, int num_procs, __u64 cgroup_id) {
    if (!redis_ctx) return -1;
    char value[1024];

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    __u64 current_timestamp_ms = (__u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    __u64 total_rss_kb = rss_bytes / 1024;
    __u64 total_cpu_ms = cpu_ns / 1000000;
    __u64 cpu_usec = cpu_ns / 1000;

    snprintf(value, sizeof(value),
        "{"
        "\"event\":\"RESOURCE_SAMPLE\","
        "\"timestamp\":%llu,"
        "\"level\":%u,"
        "\"target_pid\":%llu,"
        "\"total_rss_kb\":%llu,"
        "\"total_cpu_user_ms\":%llu,"
        "\"total_cpu_sys_ms\":0,"
        "\"num_processes\":%d,"
        "\"cgroup_memory_bytes\":%llu,"
        "\"cgroup_memory_peak_bytes\":%llu,"
        "\"cgroup_cpu_usage_usec\":%llu"
        "}",
        current_timestamp_ms, level, target_id, 
        total_rss_kb, total_cpu_ms, num_procs,
        rss_bytes, rss_bytes, cpu_usec
    );

    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL_RESOURCE, value);
    if (reply) freeReplyObject(reply);
    return 0;
}

//聚合逻辑
struct agent_agg {
    __u32 agent_id;
    __u64 total_cpu_ns;
    __u64 total_rss_bytes;
    int num_processes;
    __u64 cgroup_id;
};

void fetch_and_ship_resources(int res_fd) {
    if (!redis_ctx || res_fd < 0) return;
    
    struct res_key key = {0}, next_key;
    struct res_val val;
    
    // 用户态聚合缓存
    struct agent_agg aggs[128] = {0};
    int agg_count = 0;

    __u64 sys_cpu_ns = 0;
    __u64 sys_rss_bytes = 0;
    int sys_procs = 0;

    // 遍历内核中所有 PID 级原子数据
    while (bpf_map_get_next_key(res_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(res_fd, &next_key, &val) == 0) {
            
    __u32 current_pid = (__u32)next_key.id;
    __u64 real_rss = get_process_rss_bytes(current_pid);

    ship_resource_sample(RES_LEVEL_PID, next_key.id, val.cpu_time_ns, real_rss, 1, val.cgroup_id);

            // 聚合成 Agent 级
            int found = -1;
            for (int i=0; i<agg_count; i++) {
                if (aggs[i].agent_id == val.agent_id) { found = i; break; }
            }
            if (found == -1 && agg_count < 128) {
                found = agg_count++;
                aggs[found].agent_id = val.agent_id;
                aggs[found].cgroup_id = val.cgroup_id;
            }
            if (found != -1) {
                aggs[found].total_cpu_ns += val.cpu_time_ns;
                aggs[found].total_rss_bytes += real_rss;
                aggs[found].num_processes += 1;
            }

            // 聚合成全局系统级
            sys_cpu_ns += val.cpu_time_ns;
            sys_rss_bytes += real_rss;
            sys_procs += 1;
        }
        key = next_key;
    }

    for (int i = 0; i < agg_count; i++) {
        // 推送 智能体进程树级
        ship_resource_sample(RES_LEVEL_AGENT, aggs[i].agent_id, aggs[i].total_cpu_ns, aggs[i].total_rss_bytes, aggs[i].num_processes, aggs[i].cgroup_id);
        
        // 推送 Cgroup 级
        ship_resource_sample(RES_LEVEL_CGROUP, aggs[i].cgroup_id, aggs[i].total_cpu_ns, aggs[i].total_rss_bytes, aggs[i].num_processes, aggs[i].cgroup_id);
    }

    // 推送 全局系统级
    if (sys_procs > 0) {
        ship_resource_sample(RES_LEVEL_SYS, 0, sys_cpu_ns, sys_rss_bytes, sys_procs, 0);
    }
}