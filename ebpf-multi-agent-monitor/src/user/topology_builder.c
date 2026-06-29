#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <hiredis/hiredis.h>
#include "../bpf/common.h"
#include "topology_builder.h"
#include "redis_client.h"

#define MAX_COMPONENT_LEN 96

static unsigned long long g_message_seq = 0;

void publish_agent_comm_edge(const char *src_agent_id, const char *dst_agent_id,
                             const char *dip, int dport, unsigned long long ts_ns)
{
    if (!redis_ctx || !src_agent_id || !dst_agent_id) return;

    char edge_component[MAX_COMPONENT_LEN];
    snprintf(edge_component, sizeof(edge_component), "%s", dst_agent_id);

    redisReply *reply = redisCommand(redis_ctx, "SADD inter:edges %s:%s", src_agent_id, edge_component);
    finish_redis_command("redisCommand", reply);

    reply = redisCommand(redis_ctx,
        "HSET inter:edge:%s:%s src %s dst %s type agent_comm weight 1 "
        "protocol tcp daddr %s dport %d last_seen_ns %llu",
        src_agent_id, edge_component, src_agent_id, edge_component, dip, dport, ts_ns);
    finish_redis_command("redisCommand", reply);
}

void publish_message_event(struct agent_state *state, const char *protocol, const char *msg_type,
                           const char *data, unsigned int bytes, unsigned long long ts_ns,
                           unsigned int pid, unsigned int tid)
{
    char escaped_data[MAX_STREAM_DATA], dst_component[MAX_COMPONENT_LEN];
    char msg_id[64], comm[32];

    if (!redis_ctx || !state) return;

    sanitize_component(protocol, dst_component, sizeof(dst_component));
    if (dst_component[0] == '\0') {
        strncpy(dst_component, "llm_api", sizeof(dst_component) - 1);
        dst_component[sizeof(dst_component) - 1] = '\0';
    }

    snprintf(msg_id, sizeof(msg_id), "msg_%06llu", ++g_message_seq);
    json_escape_bytes(data, bounded_strnlen_local(data, MAX_STREAM_DATA - 1), escaped_data, sizeof(escaped_data));
    shell_escape(state->comm, comm, sizeof(comm));

    redisReply *reply = redisCommand(redis_ctx,
        "XADD inter:messages * msg_id %s src %s dst %s type %s protocol %s timestamp_ns %llu "
        "pid %u tid %u main_pid %u comm %s agent_id %s bytes %u data %s",
        msg_id, state->agent_id, dst_component, msg_type, protocol,
        ts_ns, pid, tid, state->main_pid, comm, state->agent_id, bytes, escaped_data);
    finish_redis_command("redisCommand", reply);

    reply = redisCommand(redis_ctx, "SADD inter:edges %s:%s", state->agent_id, dst_component);
    finish_redis_command("redisCommand", reply);

    reply = redisCommand(redis_ctx,
        "HSET inter:edge:%s:%s src %s dst %s type message weight 1 last_seen_ns %llu",
        state->agent_id, dst_component, state->agent_id, dst_component, ts_ns);
    finish_redis_command("redisCommand", reply);

    reply = redisCommand(redis_ctx, "HINCRBY inter:edge:%s:%s total_messages 1",
                         state->agent_id, dst_component);
    finish_redis_command("redisCommand", reply);

    reply = redisCommand(redis_ctx, "HINCRBY inter:edge:%s:%s total_bytes %u",
                         state->agent_id, dst_component, bytes);
    finish_redis_command("redisCommand", reply);
}

void publish_inter_event(struct agent_state *state, const struct sys_event *event)
{
    char comm[32], filename[1025], dip[64];
    const char *event_type = event_stream_type(event->event_type);
    const char *subtype = event_stream_subtype(event->event_type);

    if (!redis_ctx || !state) return;

    shell_escape(event->comm, comm, sizeof(comm));
    shell_escape(event->filename, filename, sizeof(filename));

    redisReply *reply = NULL;
    switch (event->event_type) {
    case EVENT_EXECVE:
    case EVENT_OPEN:
    case EVENT_UNLINK:
    case EVENT_CHMOD:
        reply = redisCommand(redis_ctx,
            "XADD inter:events * event_type %s subtype %s timestamp_ns %llu pid %u tid %u comm %s filename %s parent_pid %u agent_id %s parent_agent_id %u parent_agent_name %s",
            event_type, subtype, event->timestamp, event->pid, event->pid, comm, filename,
            event->child_pid, state->agent_id, event->parent_agent_id, event->parent_agent_name);
        break;
    case EVENT_FORK:
        reply = redisCommand(redis_ctx,
            "XADD inter:events * event_type %s subtype %s timestamp_ns %llu pid %u tid %u comm %s parent_pid %u child_pid %u agent_id %s parent_agent_id %u parent_agent_name %s",
            event_type, subtype, event->timestamp, event->pid, event->pid, comm,
            event->pid, event->child_pid, state->agent_id, event->parent_agent_id, event->parent_agent_name);
        break;
    case EVENT_CONNECT:
        format_ipv4(event->connect.dip, dip, sizeof(dip));
        reply = redisCommand(redis_ctx,
            "XADD inter:events * event_type %s subtype %s timestamp_ns %llu pid %u tid %u comm %s family %d daddr %s dport %d agent_id %s parent_agent_id %u parent_agent_name %s",
            event_type, subtype, event->timestamp, event->pid, event->pid, comm,
            event->connect.family, dip, event->connect.dport, state->agent_id,
            event->parent_agent_id, event->parent_agent_name);
        break;
    case EVENT_AGENT_COMM:
        format_ipv4(event->connect.dip, dip, sizeof(dip));
        {
            char peer_agent_str[MAX_AGENT_ID_LEN];
            snprintf(peer_agent_str, sizeof(peer_agent_str), "agent_%u",
                     event->peer_agent_id ? (event->peer_agent_id & 0x7FFFFFFF) : event->peer_pid);
            reply = redisCommand(redis_ctx,
                "XADD inter:events * event_type %s subtype %s timestamp_ns %llu pid %u tid %u comm %s "
                "family %d daddr %s dport %d agent_id %s "
                "parent_agent_id %u parent_agent_name %s "
                "peer_agent_id %u peer_pid %u peer_agent %s",
                event_type, subtype, event->timestamp, event->pid, event->pid, comm,
                event->connect.family, dip, event->connect.dport, state->agent_id,
                event->parent_agent_id, event->parent_agent_name,
                event->peer_agent_id, event->peer_pid, peer_agent_str);
            publish_agent_comm_edge(state->agent_id, peer_agent_str,
                                    dip, event->connect.dport, event->timestamp);
        }
        break;
    default:
        return;
    }

    finish_redis_command("redisCommand", reply);
}
