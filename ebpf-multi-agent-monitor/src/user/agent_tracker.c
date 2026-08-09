#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hiredis/hiredis.h>
#include "../bpf/common.h"
#include "agent_tracker.h"
#include "redis_client.h"

static struct agent_state g_agents[MAX_TRACKED_AGENTS];
static const char *g_agent_markers[] = {
    "claude", "codex", "gemini", "anthropic",
    "openai", "deepseek", "aider", "cursor", "qwen",
};

void agent_tracker_init(void)
{
    memset(g_agents, 0, sizeof(g_agents));
}

struct agent_state *find_agent_by_pid(unsigned int pid)
{
    for (unsigned int i = 0; i < MAX_TRACKED_AGENTS; i++) {
        if (g_agents[i].in_use && g_agents[i].pid == pid)
            return &g_agents[i];
    }
    return NULL;
}

struct agent_state *allocate_agent_slot(void)
{
    for (unsigned int i = 0; i < MAX_TRACKED_AGENTS; i++) {
        if (!g_agents[i].in_use) {
            memset(&g_agents[i], 0, sizeof(g_agents[i]));
            g_agents[i].in_use = 1;
            return &g_agents[i];
        }
    }
    return NULL;
}

int cmdline_contains_agent_marker(unsigned int pid, char *comm_out, size_t comm_out_len)
{
    char path[64], cmdline[2048], lowered[2048];
    FILE *fp;
    size_t read_len, i;

    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
    fp = fopen(path, "r");
    if (!fp) return 0;
    read_len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);
    if (read_len == 0) return 0;
    cmdline[read_len] = '\0';
    for (i = 0; i < read_len; i++) {
        if (cmdline[i] == '\0') cmdline[i] = ' ';
    }
    lowercase_copy(cmdline, lowered, sizeof(lowered));

    for (size_t marker_idx = 0; marker_idx < sizeof(g_agent_markers) / sizeof(g_agent_markers[0]); marker_idx++) {
        if (strstr(lowered, g_agent_markers[marker_idx]) != NULL) {
            if (comm_out && comm_out_len > 0) {
                strncpy(comm_out, g_agent_markers[marker_idx], comm_out_len - 1);
                comm_out[comm_out_len - 1] = '\0';
            }
            return 1;
        }
    }
    return 0;
}

void publish_agent_registration(struct agent_state *state)
{
    char agent_id[MAX_AGENT_ID_LEN];
    char comm[32];
    char workspace[MAX_WORKSPACE_LEN * 2];
    char key[128];

    if (!redis_ctx || !state || !state->in_use) return;

    shell_escape(state->agent_id, agent_id, sizeof(agent_id));
    shell_escape(state->comm, comm, sizeof(comm));
    shell_escape(state->workspace, workspace, sizeof(workspace));

    redisReply *reply = redisCommand(redis_ctx, "SADD inter:agents %s", state->agent_id);
    finish_redis_command("redisCommand", reply);

    snprintf(key, sizeof(key), "inter:agent:%s", state->agent_id);
    reply = redisCommand(redis_ctx,
        "HSET %s agent_id %s parent_agent_id %s main_pid %u comm %s workspace %s "
        "depth %d is_sub_agent %d status active group default",
        key, state->agent_id, state->parent_agent_id,
        state->main_pid, state->comm, state->workspace,
        state->depth, state->is_sub_agent);
    finish_redis_command("redisCommand", reply);
}

struct agent_state *get_or_create_agent(unsigned int pid, unsigned int ppid,
                                        const char *comm, unsigned long long ts_ns,
                                        __u32 parent_agent_id, const char *parent_agent_name)
{
    struct agent_state *state = find_agent_by_pid(pid);
    struct agent_state *parent_state = NULL;
    char detected_comm[16];
    (void)parent_agent_name;

    if (state) {
        if (ts_ns > state->metrics.last_active_ns)
            state->metrics.last_active_ns = ts_ns;
        return state;
    }

    parent_state = find_agent_by_pid(ppid);
    if (!parent_state && !cmdline_contains_agent_marker(pid, detected_comm, sizeof(detected_comm)))
        return NULL;

    state = allocate_agent_slot();
    if (!state) return NULL;

    state->pid = pid;
    state->metrics.window_start_ns = ts_ns;
    state->metrics.last_active_ns = ts_ns;

    if (parent_agent_id != 0)
        snprintf(state->parent_agent_id, sizeof(state->parent_agent_id), "agent_%u", parent_agent_id);

    if (parent_state) {
        state->main_pid = parent_state->main_pid;
        strncpy(state->agent_id, parent_state->agent_id, sizeof(state->agent_id) - 1);
        strncpy(state->workspace, parent_state->workspace, sizeof(state->workspace) - 1);
        strncpy(state->comm, comm && comm[0] ? comm : parent_state->comm, sizeof(state->comm) - 1);
        if (parent_agent_id == 0 && parent_state->parent_agent_id[0])
            strncpy(state->parent_agent_id, parent_state->parent_agent_id, sizeof(state->parent_agent_id) - 1);
        state->depth = parent_state->depth + 1;
        state->is_sub_agent = 1;
        return state;
    }

    state->main_pid = pid;
    snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", pid);
    strncpy(state->workspace, workspace_root(), sizeof(state->workspace) - 1);
    strncpy(state->comm, comm && comm[0] ? comm : detected_comm, sizeof(state->comm) - 1);
    state->depth = 0;
    state->is_sub_agent = 0;

    publish_agent_registration(state);
    return state;
}

struct agent_state *get_or_create_ssl_fallback_agent(const struct probe_SSL_data_t *event)
{
    if (!event) return NULL;

    struct agent_state *state = find_agent_by_pid(event->pid);
    if (state) {
        if (event->timestamp_ns > state->metrics.last_active_ns)
            state->metrics.last_active_ns = event->timestamp_ns;
        return state;
    }

    state = allocate_agent_slot();
    if (!state) return NULL;

    state->pid = event->pid;
    state->main_pid = event->pid;
    state->metrics.window_start_ns = event->timestamp_ns;
    state->metrics.last_active_ns = event->timestamp_ns;

    if (event->agent_id != 0)
        snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", event->agent_id);
    else
        snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", event->pid);

    strncpy(state->workspace, workspace_root(), sizeof(state->workspace) - 1);
    state->workspace[sizeof(state->workspace) - 1] = '\0';

    if (event->comm[0])
        strncpy(state->comm, event->comm, sizeof(state->comm) - 1);
    else if (event->agent_name[0])
        strncpy(state->comm, event->agent_name, sizeof(state->comm) - 1);
    else
        strncpy(state->comm, "ssl", sizeof(state->comm) - 1);
    state->comm[sizeof(state->comm) - 1] = '\0';

    publish_agent_registration(state);
    return state;
}

struct agent_state *create_behavioral_agent(unsigned int pid, const char *comm)
{
    struct agent_state *state = allocate_agent_slot();
    if (!state) return NULL;

    state->pid = pid;
    state->main_pid = pid;
    state->is_sub_agent = 1;
    state->depth = 0;

    snprintf(state->agent_id, sizeof(state->agent_id), "behavioral_%u", pid);

    char cwd_path[64];
    snprintf(cwd_path, sizeof(cwd_path), "/proc/%u/cwd", pid);
    ssize_t len = readlink(cwd_path, state->workspace, sizeof(state->workspace) - 1);
    if (len > 0)
        state->workspace[len] = '\0';
    else
        strncpy(state->workspace, "/", sizeof(state->workspace) - 1);

    strncpy(state->comm, comm && comm[0] ? comm : "behavioral", sizeof(state->comm) - 1);
    state->comm[sizeof(state->comm) - 1] = '\0';

    printf("[DISCOVERY] 行为识别发现新智能体 PID=%u comm=%s\n", pid, state->comm);
    publish_agent_registration(state);
    return state;
}
