#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include "../bpf/common.h"
#include "redis_client.h"
#include "agent_tracker.h"
#include "metrics_aggregator.h"
#include "topology_builder.h"
#include "event_serializer.h"

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_CHANNEL "ebpf_events"

redisContext *redis_ctx = NULL;

void finish_redis_command(const char *op_name, redisReply *reply)
{
    if (!reply) {
        if (redis_ctx && redis_ctx->err)
            fprintf(stderr, "[REDIS] %s failed: %s\n", op_name, redis_ctx->errstr);
        else
            fprintf(stderr, "[REDIS] %s failed: empty reply\n", op_name);
        return;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        fprintf(stderr, "[REDIS] %s error: %s\n", op_name, reply->str ? reply->str : "(unknown)");
    }
    freeReplyObject(reply);
}

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
    agent_tracker_init();
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

/* ── SSL chunk reassembly (N-chunk full capture) ── */
#define REASSEMBLY_STREAMS_MAX  64
#define REASSEMBLY_TIMEOUT_SEC  5
#define MAX_CHUNKS_PER_STREAM   32

struct chunk_hold {
    __u64 stream_key;
    time_t first_seen;
    int   in_use;
    __u32 pid, tid, uid, agent_id;
    char  agent_name[MAX_AGENT_NAME_LEN];
    __u32 total_len;
    int   rw;
    char  comm[MAX_COMM_LEN];
    __u16 total_chunks;
    __u32 received_mask;
    __u8 *chunks[MAX_CHUNKS_PER_STREAM];
    __u32 chunk_lens[MAX_CHUNKS_PER_STREAM];
};
static struct chunk_hold g_hold[REASSEMBLY_STREAMS_MAX];

static __u64 stream_key(__u32 tid, __u64 timestamp_ns)
{
    return ((__u64)tid << 32) | (timestamp_ns & 0xFFFFFFFFULL);
}

static struct chunk_hold *hold_find(__u32 tid, __u64 ts_ns)
{
    __u64 key = stream_key(tid, ts_ns);
    for (int i = 0; i < REASSEMBLY_STREAMS_MAX; i++)
        if (g_hold[i].in_use && g_hold[i].stream_key == key)
            return &g_hold[i];
    return NULL;
}

static struct chunk_hold *hold_alloc(__u32 tid, __u64 ts_ns)
{
    __u64 key = stream_key(tid, ts_ns);
    time_t now = time(NULL);
    for (int i = 0; i < REASSEMBLY_STREAMS_MAX; i++) {
        if (!g_hold[i].in_use ||
            now - g_hold[i].first_seen > REASSEMBLY_TIMEOUT_SEC) {
            for (int j = 0; j < g_hold[i].total_chunks; j++)
                free(g_hold[i].chunks[j]);
            memset(&g_hold[i], 0, sizeof(g_hold[i]));
            g_hold[i].stream_key = key;
            g_hold[i].first_seen  = now;
            g_hold[i].in_use      = 1;
            return &g_hold[i];
        }
    }
    return NULL;
}

static void hold_free(__u32 tid, __u64 ts_ns)
{
    struct chunk_hold *h = hold_find(tid, ts_ns);
    if (h) {
        for (int j = 0; j < h->total_chunks; j++)
            free(h->chunks[j]);
        h->in_use = 0;
    }
}

int ship_sys_event(struct sys_event *event)
{
    char value[2048], escaped_filename[1025], escaped_comm[32];
    struct agent_state *state;

    if (!redis_ctx || !event) return -1;

    state = get_or_create_agent(event->pid, event->child_pid, event->comm, event->timestamp,
                                event->parent_agent_id, event->parent_agent_name);
    if (state) {
        update_metrics_for_sys_event(state, event);
        publish_metrics_if_needed(state, event->timestamp);
        publish_inter_event(state, event);
    }

    {
        char escaped_agent_name[65];
        json_escape(event->comm, escaped_comm, sizeof(escaped_comm));

        redisReply *reply;
        if (event->event_type == EVENT_CONNECT || event->event_type == EVENT_AGENT_COMM) {
            char dip[64];
            format_ipv4(event->connect.dip, dip, sizeof(dip));
            snprintf(value, sizeof(value),
                "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\","
                "\"dip\":\"%s\",\"dport\":%d,\"agent_id\":\"%s\",\"parent_agent_id\":%u,"
                "\"parent_agent_name\":\"%s\",\"main_pid\":%u,\"depth\":%d,\"is_sub_agent\":%d,"
                "\"peer_agent_id\":%u,\"peer_pid\":%u}",
                event->event_type, event->pid, event->child_pid, event->uid, event->timestamp,
                escaped_comm, dip, event->connect.dport,
                state ? state->agent_id : "", event->parent_agent_id, event->parent_agent_name,
                state ? state->main_pid : event->pid,
                state ? state->depth : -1, state ? state->is_sub_agent : -1,
                event->peer_agent_id, event->peer_pid);
        } else {
            json_escape(event->filename, escaped_filename, sizeof(escaped_filename));
            snprintf(value, sizeof(value),
                "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\","
                "\"filename\":\"%s\",\"agent_id\":\"%s\",\"parent_agent_id\":%u,"
                "\"parent_agent_name\":\"%s\",\"main_pid\":%u,\"depth\":%d,\"is_sub_agent\":%d}",
                event->event_type, event->pid, event->child_pid, event->uid, event->timestamp,
                escaped_comm, escaped_filename,
                state ? state->agent_id : "", event->parent_agent_id, event->parent_agent_name,
                state ? state->main_pid : event->pid,
                state ? state->depth : -1, state ? state->is_sub_agent : -1);
        }

        json_escape(event->agent_name, escaped_agent_name, sizeof(escaped_agent_name));
        reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
        finish_redis_command("redisCommand", reply);
    }

    return 0;
}

int ship_ssl_event(struct probe_SSL_data_t *event)
{
    if (!redis_ctx || !event) return -1;
    if (event->buf_size == 0 || event->buf_filled == 0 || event->is_handshake || event->rw == 2)
        return 0;

    uint32_t mapped_event_type = (event->rw == 0) ? EVENT_SSL_READ : EVENT_SSL_WRITE;

    /* ── chunk reassembly (N-chunk full capture) ── */
    if (event->chunk_total > 1) {
        struct chunk_hold *h = hold_find(event->tid, event->timestamp_ns);
        if (!h) {
            h = hold_alloc(event->tid, event->timestamp_ns);
            if (!h) return -1;
            h->pid          = event->pid;
            h->tid          = event->tid;
            h->uid          = event->uid;
            h->agent_id     = event->agent_id;
            __builtin_memcpy(h->agent_name, event->agent_name, sizeof(h->agent_name));
            h->total_len    = event->len;
            h->rw           = event->rw;
            __builtin_memcpy(h->comm, event->comm, sizeof(h->comm));
            h->total_chunks = event->chunk_total;
        }

        __u16 idx = event->chunk_index;
        if (idx < MAX_CHUNKS_PER_STREAM && !h->chunks[idx]) {
            h->chunks[idx] = malloc(event->buf_size);
            if (h->chunks[idx]) {
                memcpy(h->chunks[idx], event->buf, event->buf_size);
                h->chunk_lens[idx] = event->buf_size;
                h->received_mask |= (1u << idx);
            }
        }

        /* check if all chunks arrived */
        __u32 full_mask = (h->total_chunks < 32)
            ? ((1u << h->total_chunks) - 1)
            : 0xFFFFFFFFu;
        if ((h->received_mask & full_mask) != full_mask)
            return 0;  /* not yet complete */

        /* ── all chunks arrived → concatenate → base64 → ship ── */
        __u32 combined_len = 0;
        for (__u16 i = 0; i < h->total_chunks; i++)
            combined_len += h->chunk_lens[i];

        __u8 *combined = malloc(combined_len);
        if (!combined) { hold_free(event->tid, event->timestamp_ns); return -1; }
        __u32 pos = 0;
        for (__u16 i = 0; i < h->total_chunks; i++) {
            memcpy(combined + pos, h->chunks[i], h->chunk_lens[i]);
            pos += h->chunk_lens[i];
        }

        int b64_alloc = 4 * (combined_len + 2) / 3 + 16;
        char *b64 = malloc(b64_alloc);
        if (!b64) { free(combined); hold_free(event->tid, event->timestamp_ns); return -1; }
        base64_encode(combined, combined_len, b64);
        free(combined);

        struct agent_state *state = get_or_create_agent(event->pid, event->pid, event->comm,
                                                        event->timestamp_ns, 0, "");
        if (!state) state = get_or_create_ssl_fallback_agent(event);
        if (state) {
            update_metrics_for_ssl_event(state, mapped_event_type,
                                         (const char *)h->chunks[0], h->chunk_lens[0]);
            publish_metrics_if_needed(state, event->timestamp_ns);
            publish_message_event(state, "ssl",
                mapped_event_type == EVENT_SSL_WRITE ? "prompt" : "response",
                b64, h->total_len, event->timestamp_ns, event->pid, event->tid);

            char escaped_comm2[32];
            json_escape(event->comm, escaped_comm2, sizeof(escaped_comm2));
            size_t ssl_msg_size = b64_alloc + 2048;
            char *ssl_msg_value = malloc(ssl_msg_size);
            if (ssl_msg_value) {
                snprintf(ssl_msg_value, ssl_msg_size,
                    "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"timestamp\":%llu,\"comm\":\"%s\","
                    "\"data_len\":%u,\"data\":\"%s\",\"agent_id\":\"%s\",\"main_pid\":%u}",
                    mapped_event_type, event->pid, event->pid, event->timestamp_ns,
                    escaped_comm2, h->total_len, b64, state->agent_id, state->main_pid);
                redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, ssl_msg_value);
                finish_redis_command("redisCommand", reply);
                free(ssl_msg_value);
            }
        }

        free(b64);
        hold_free(event->tid, event->timestamp_ns);
        return 0;
    }

ship_single:
    /* ── original single-chunk path ── */
    size_t b64_len = 4 * ((event->buf_size + 2) / 3) + 1;
    char *b64_data = malloc(b64_len);
    if (!b64_data) return -1;
    base64_encode((const unsigned char *)event->buf, event->buf_size, b64_data);

    struct agent_state *state = get_or_create_agent(event->pid, event->pid, event->comm,
                                                    event->timestamp_ns, 0, "");
    if (!state) state = get_or_create_ssl_fallback_agent(event);
    if (state) {
        update_metrics_for_ssl_event(state, mapped_event_type, (const char *)event->buf, event->buf_size);
        publish_metrics_if_needed(state, event->timestamp_ns);
        publish_message_event(state, "ssl",
            mapped_event_type == EVENT_SSL_WRITE ? "prompt" : "response",
            b64_data, event->buf_size, event->timestamp_ns, event->pid, event->tid);

        {
            char escaped_comm2[32], *ssl_msg_value;
            size_t ssl_msg_size = b64_len + 2048;
            json_escape(event->comm, escaped_comm2, sizeof(escaped_comm2));
            ssl_msg_value = malloc(ssl_msg_size);
            if (ssl_msg_value) {
                snprintf(ssl_msg_value, ssl_msg_size,
                    "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"timestamp\":%llu,\"comm\":\"%s\","
                    "\"data_len\":%u,\"data\":\"%s\",\"agent_id\":\"%s\",\"main_pid\":%u}",
                    mapped_event_type, event->pid, event->pid, event->timestamp_ns,
                    escaped_comm2, event->buf_size, b64_data, state->agent_id, state->main_pid);
                redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, ssl_msg_value);
                finish_redis_command("redisCommand", reply);
                free(ssl_msg_value);
            }
        }
    }

    free(b64_data);
    return 0;
}

int ship_raw_event(struct raw_data_event *event)
{
    char escaped_agent_name[65], escaped_comm[32];
    struct agent_state *state;

    if (!redis_ctx || !event) return -1;

    uint32_t mapped_event_type;
    if (event->source == RAW_SRC_STDIO)
        mapped_event_type = (event->direction == 0) ? EVENT_STDIO_READ : EVENT_STDIO_WRITE;
    else
        mapped_event_type = (event->direction == 0) ? EVENT_TCP_RECV : EVENT_TCP_SEND;

    json_escape(event->agent_name, escaped_agent_name, sizeof(escaped_agent_name));
    json_escape(event->comm, escaped_comm, sizeof(escaped_comm));

    if (event->buf_filled && event->buf_size > 0) {
        size_t b64_len = 4 * ((event->buf_size + 2) / 3) + 1;
        char *b64_data = malloc(b64_len);
        if (!b64_data) return -1;
        base64_encode(event->buf, event->buf_size, b64_data);

        size_t json_buffer_size = b64_len + 1024;
        char *value = malloc(json_buffer_size);
        if (!value) { free(b64_data); return -1; }

        snprintf(value, json_buffer_size,
            "{\"type\":%u,\"pid\":%u,\"tid\":%u,\"timestamp\":%llu,\"comm\":\"%s\","
            "\"data_len\":%u,\"fd\":%u,\"source\":%u,\"direction\":%d,"
            "\"agent_id\":%u,\"agent_name\":\"%s\",\"parent_agent_id\":%u,"
            "\"parent_agent_name\":\"%s\",\"peer_pid\":%u,\"data\":\"%s\"}",
            mapped_event_type, event->pid, event->tid, event->timestamp_ns,
            escaped_comm, event->data_len, event->fd, event->source,
            event->direction, event->agent_id, escaped_agent_name,
            event->parent_agent_id, event->parent_agent_name,
            event->peer_pid, b64_data);

        redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
        finish_redis_command("redisCommand", reply);
        free(value);

        state = get_or_create_agent(event->pid, event->pid, event->comm, event->timestamp_ns,
                                     event->parent_agent_id, (const char *)event->parent_agent_name);
        if (!state) {
            state = allocate_agent_slot();
            if (state) {
                state->in_use = 1;
                state->pid = event->pid;
                state->main_pid = event->pid;
                state->metrics.window_start_ns = event->timestamp_ns;
                state->metrics.last_active_ns = event->timestamp_ns;
                snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", event->pid);
                strncpy(state->workspace, workspace_root(), sizeof(state->workspace) - 1);
                strncpy(state->comm, event->comm && event->comm[0] ? event->comm : "raw_proto",
                        sizeof(state->comm) - 1);
                publish_agent_registration(state);
            }
        }

        if (state) {
            if (event->direction == 0) {
                state->metrics.msg_recv_count++;
                state->metrics.net_recv_count++;
            } else {
                state->metrics.msg_sent_count++;
                state->metrics.net_send_count++;
            }
            state->metrics.api_call_count++;
            publish_metrics_if_needed(state, event->timestamp_ns);

            char escaped_payload[MAX_STREAM_DATA];
            json_escape_bytes((const char *)event->buf,
                bounded_strnlen_local((const char *)event->buf, MAX_STREAM_DATA - 1),
                escaped_payload, sizeof(escaped_payload));

            const char *protocol = (event->source == RAW_SRC_STDIO) ? "stdio" : "tcp";
            const char *msg_type = (event->direction == 0) ? "recv" : "send";
            publish_message_event(state, protocol, msg_type, escaped_payload,
                                  event->buf_size, event->timestamp_ns, event->pid, event->tid);
        }

        free(b64_data);
    }

    return 0;
}
