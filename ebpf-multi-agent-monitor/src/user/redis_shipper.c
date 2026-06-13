#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <hiredis/hiredis.h>

#include "../bpf/common.h"

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_CHANNEL "ebpf_events"
#define REDIS_CHANNEL_BEHAVIOR "ebpf_behavior_events"
#define REDIS_CHANNEL_RESOURCE "ebpf_resource_events"
#define MAX_TRACKED_AGENTS 128
#define MAX_UNIQUE_FILES 64
#define MAX_AGENT_ID_LEN 64
#define MAX_WORKSPACE_LEN 256
#define MAX_COMPONENT_LEN 96
#define MAX_STREAM_DATA 512
#define METRIC_WINDOW_NS (30ULL * 1000ULL * 1000ULL * 1000ULL)

static redisContext *redis_ctx = NULL;

struct agent_metrics {
    double cpu_usage;
    double memory_usage;
    unsigned int proc_exec_count;
    unsigned int proc_fork_count;
    unsigned int fs_open_count;
    unsigned int fs_read_count;
    unsigned int fs_write_count;
    unsigned int fs_unlink_count;
    unsigned int net_connect_count;
    unsigned int net_send_count;
    unsigned int net_recv_count;
    unsigned int api_call_count;
    unsigned int msg_sent_count;
    unsigned int msg_recv_count;
    unsigned int shell_exec_count;
    unsigned int sensitive_file_count;
    unsigned int workspace_violation;
    unsigned int unique_files_count;
    unsigned long long window_start_ns;
    unsigned long long last_active_ns;
    char unique_files[MAX_UNIQUE_FILES][MAX_PATH_LEN];
};

struct agent_state {
    int in_use;
    unsigned int pid;
    unsigned int main_pid;
    char agent_id[MAX_AGENT_ID_LEN];
    char comm[MAX_COMM_LEN];
    char workspace[MAX_WORKSPACE_LEN];
    struct agent_metrics metrics;
};

struct agent_agg {
    __u32 agent_id;
    __u64 total_cpu_ns;
    __u64 total_rss_bytes;
    int num_processes;
    __u64 cgroup_id;
};

static struct agent_state g_agents[MAX_TRACKED_AGENTS];
static unsigned long long g_message_seq = 0;
static const char *g_workspace_root = NULL;
static const char *g_agent_markers[] = {
    "claude",
    "codex",
    "gemini",
    "anthropic",
    "openai",
    "deepseek",
    "aider",
    "cursor",
    "qwen",
};

static struct agent_state *get_or_create_ssl_fallback_agent(const struct probe_SSL_data_t *event);

static void finish_redis_command(const char *op_name, redisReply *reply)
{
    if (!reply) {
        if (redis_ctx && redis_ctx->err) {
            fprintf(stderr, "[REDIS] %s failed: %s\n", op_name, redis_ctx->errstr);
        } else {
            fprintf(stderr, "[REDIS] %s failed: empty reply\n", op_name);
        }
        return;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        fprintf(stderr, "[REDIS] %s error: %s\n", op_name, reply->str ? reply->str : "(unknown)");
    }
    freeReplyObject(reply);
}

static const char *workspace_root(void)
{
    if (g_workspace_root && g_workspace_root[0]) {
        return g_workspace_root;
    }
    g_workspace_root = getenv("MONITOR_WORKSPACE");
    if (!g_workspace_root || !g_workspace_root[0]) {
        g_workspace_root = "/mnt/e/os2026";
    }
    return g_workspace_root;
}

static size_t bounded_strnlen_local(const char *src, size_t max_len)
{
    size_t si = 0;

    if (!src) {
        return 0;
    }
    while (si < max_len && src[si] != '\0') {
        si++;
    }
    return si;
}

static void json_escape_bytes(const char *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t si = 0;
    size_t di = 0;

    if (!dst || dst_len == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    while (si < src_len && di + 1 < dst_len) {
        unsigned char c = (unsigned char)src[si++];
        if (c == '\\' || c == '"') {
            if (di + 2 >= dst_len) {
                break;
            }
            dst[di++] = '\\';
            dst[di++] = (char)c;
            continue;
        }
        if (c == '\n') {
            if (di + 2 >= dst_len) {
                break;
            }
            dst[di++] = '\\';
            dst[di++] = 'n';
            continue;
        }
        if (c == '\r') {
            if (di + 2 >= dst_len) {
                break;
            }
            dst[di++] = '\\';
            dst[di++] = 'r';
            continue;
        }
        if (c == '\t') {
            if (di + 2 >= dst_len) {
                break;
            }
            dst[di++] = '\\';
            dst[di++] = 't';
            continue;
        }
        if (iscntrl(c)) {
            dst[di++] = ' ';
            continue;
        }
        dst[di++] = (char)c;
    }

    dst[di] = '\0';
}

static void json_escape(const char *src, char *dst, size_t dst_len)
{
    json_escape_bytes(src, src ? strlen(src) : 0, dst, dst_len);
}

static void shell_escape_bytes(const char *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t si = 0;
    size_t di = 0;

    if (!dst || dst_len == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    while (si < src_len && di + 1 < dst_len) {
        unsigned char c = (unsigned char)src[si++];
        if (c == '\\' || c == '"' || c == '$' || c == '`') {
            if (di + 2 >= dst_len) {
                break;
            }
            dst[di++] = '\\';
            dst[di++] = (char)c;
            continue;
        }
        if (c == '\n' || c == '\r' || c == '\t' || iscntrl(c)) {
            dst[di++] = ' ';
            continue;
        }
        dst[di++] = (char)c;
    }

    dst[di] = '\0';
}

static void shell_escape(const char *src, char *dst, size_t dst_len)
{
    shell_escape_bytes(src, src ? strlen(src) : 0, dst, dst_len);
}

static void lowercase_copy(const char *src, char *dst, size_t dst_len)
{
    size_t i = 0;

    if (!dst || dst_len == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    while (src[i] != '\0' && i + 1 < dst_len) {
        dst[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[i] = '\0';
}

static void sanitize_component(const char *src, char *dst, size_t dst_len)
{
    size_t si = 0;
    size_t di = 0;

    if (!dst || dst_len == 0) {
        return;
    }

    while (src && src[si] != '\0' && di + 1 < dst_len) {
        unsigned char c = (unsigned char)src[si++];
        if (isalnum(c)) {
            dst[di++] = (char)c;
        } else {
            dst[di++] = '_';
        }
    }
    dst[di] = '\0';
}

static void format_ipv4(const char raw[46], char *out, size_t out_len)
{
    const unsigned char *ip = (const unsigned char *)raw;
    if (!out || out_len == 0) {
        return;
    }
    snprintf(out, out_len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static int path_starts_with(const char *path, const char *prefix)
{
    size_t prefix_len;

    if (!path || !prefix) {
        return 0;
    }
    prefix_len = strlen(prefix);
    if (prefix_len == 0) {
        return 0;
    }
    return strncmp(path, prefix, prefix_len) == 0;
}

static int path_is_sensitive(const char *path)
{
    static const char *markers[] = {
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/var/run/docker.sock",
        "/.ssh/",
        "/.aws/credentials",
        "/.kube/config",
        ".env",
    };
    size_t i;

    if (!path || !path[0]) {
        return 0;
    }
    for (i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
        if (strstr(path, markers[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

static int path_is_workspace_violation(const char *path)
{
    if (!path || !path[0] || path[0] != '/') {
        return 0;
    }
    if (path_starts_with(path, workspace_root())) {
        return 0;
    }
    if (path_starts_with(path, "/tmp/") || path_starts_with(path, "/var/tmp/")) {
        return 0;
    }
    return 1;
}

static void remember_unique_file(struct agent_metrics *metrics, const char *path)
{
    unsigned int i;

    if (!metrics || !path || !path[0]) {
        return;
    }
    for (i = 0; i < metrics->unique_files_count && i < MAX_UNIQUE_FILES; i++) {
        if (strncmp(metrics->unique_files[i], path, MAX_PATH_LEN) == 0) {
            return;
        }
    }
    if (metrics->unique_files_count < MAX_UNIQUE_FILES) {
        strncpy(metrics->unique_files[metrics->unique_files_count], path, MAX_PATH_LEN - 1);
        metrics->unique_files[metrics->unique_files_count][MAX_PATH_LEN - 1] = '\0';
        metrics->unique_files_count++;
    }
}

static const char *event_stream_type(unsigned int event_type)
{
    switch (event_type) {
    case EVENT_EXECVE:
    case EVENT_FORK:
        return "proc";
    case EVENT_OPEN:
    case EVENT_UNLINK:
    case EVENT_CHMOD:
        return "fs";
    case EVENT_CONNECT:
    case EVENT_SSL_READ:
    case EVENT_SSL_WRITE:
        return "net";
    default:
        return "unknown";
    }
}

static const char *event_stream_subtype(unsigned int event_type)
{
    switch (event_type) {
    case EVENT_EXECVE:
        return "PROC_EXEC";
    case EVENT_FORK:
        return "PROC_FORK";
    case EVENT_OPEN:
        return "FS_OPEN";
    case EVENT_UNLINK:
        return "FS_UNLINK";
    case EVENT_CONNECT:
        return "NET_CONNECT";
    case EVENT_SSL_READ:
        return "NET_RECV";
    case EVENT_SSL_WRITE:
        return "NET_SEND";
    case EVENT_CHMOD:
        return "FS_CHMOD";
    default:
        return "UNKNOWN";
    }
}

static const char *get_behavior_name(uint32_t type)
{
    switch (type) {
    case EVENT_EXECVE:
        return "PROCESS_EXECUTE";
    case EVENT_FORK:
        return "PROCESS_FORK";
    case EVENT_OPEN:
        return "FILE_OPEN";
    case EVENT_UNLINK:
        return "FILE_DELETE";
    case EVENT_CONNECT:
        return "NETWORK_CONNECT";
    case EVENT_SSL_READ:
        return "SSL_RECEIVE_RESPONSE";
    case EVENT_SSL_WRITE:
        return "SSL_SEND_PROMPT";
    case EVENT_CHMOD:
        return "PERMISSION_CHANGE";
    default:
        return "UNKNOWN_BEHAVIOR";
    }
}

static void base64_encode(const unsigned char *src, size_t len, char *out)
{
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;
    size_t j = 0;

    for (i = 0; i < len; i += 3) {
        uint32_t n = (src[i] << 16) |
                     ((i + 1 < len ? src[i + 1] : 0) << 8) |
                     (i + 2 < len ? src[i + 2] : 0);
        out[j++] = b64chars[(n >> 18) & 0x3F];
        out[j++] = b64chars[(n >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64chars[(n >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? b64chars[n & 0x3F] : '=';
    }
    out[j] = '\0';
}

static struct agent_state *find_agent_by_pid(unsigned int pid)
{
    unsigned int i;

    for (i = 0; i < MAX_TRACKED_AGENTS; i++) {
        if (g_agents[i].in_use && g_agents[i].pid == pid) {
            return &g_agents[i];
        }
    }
    return NULL;
}

static int cmdline_contains_agent_marker(unsigned int pid, char *comm_out, size_t comm_out_len)
{
    char path[64];
    char cmdline[2048];
    char lowered[2048];
    FILE *fp;
    size_t read_len;
    size_t i;
    size_t marker_idx;

    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }
    read_len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);
    if (read_len == 0) {
        return 0;
    }
    cmdline[read_len] = '\0';
    for (i = 0; i < read_len; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    lowercase_copy(cmdline, lowered, sizeof(lowered));

    for (marker_idx = 0; marker_idx < sizeof(g_agent_markers) / sizeof(g_agent_markers[0]); marker_idx++) {
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

static struct agent_state *allocate_agent_slot(void)
{
    unsigned int i;

    for (i = 0; i < MAX_TRACKED_AGENTS; i++) {
        if (!g_agents[i].in_use) {
            memset(&g_agents[i], 0, sizeof(g_agents[i]));
            g_agents[i].in_use = 1;
            return &g_agents[i];
        }
    }
    return NULL;
}

static void publish_agent_registration(struct agent_state *state)
{
    redisReply *reply;
    char agent_id[MAX_AGENT_ID_LEN];
    char comm[MAX_COMM_LEN * 2];
    char workspace[MAX_WORKSPACE_LEN * 2];
    char key[128];

    if (!redis_ctx || !state || !state->in_use) {
        return;
    }

    shell_escape(state->agent_id, agent_id, sizeof(agent_id));
    shell_escape(state->comm, comm, sizeof(comm));
    shell_escape(state->workspace, workspace, sizeof(workspace));

    reply = redisCommand(redis_ctx, "SADD inter:agents %s", state->agent_id);
    finish_redis_command("redisCommand", reply);

    snprintf(key, sizeof(key), "inter:agent:%s", state->agent_id);
    reply = redisCommand(
        redis_ctx,
        "HSET %s agent_id %s main_pid %u comm %s workspace %s status active group default",
        key,
        state->agent_id,
        state->main_pid,
        state->comm,
        state->workspace
    );
    finish_redis_command("redisCommand", reply);
}

static struct agent_state *get_or_create_agent(unsigned int pid, unsigned int ppid,
                                               const char *comm, unsigned long long ts_ns)
{
    struct agent_state *state = find_agent_by_pid(pid);
    struct agent_state *parent_state = NULL;
    char detected_comm[MAX_COMM_LEN];

    if (state) {
        if (ts_ns > state->metrics.last_active_ns) {
            state->metrics.last_active_ns = ts_ns;
        }
        return state;
    }

    parent_state = find_agent_by_pid(ppid);
    if (!parent_state && !cmdline_contains_agent_marker(pid, detected_comm, sizeof(detected_comm))) {
        return NULL;
    }

    state = allocate_agent_slot();
    if (!state) {
        return NULL;
    }

    state->pid = pid;
    state->metrics.window_start_ns = ts_ns;
    state->metrics.last_active_ns = ts_ns;

    if (parent_state) {
        state->main_pid = parent_state->main_pid;
        strncpy(state->agent_id, parent_state->agent_id, sizeof(state->agent_id) - 1);
        strncpy(state->workspace, parent_state->workspace, sizeof(state->workspace) - 1);
        strncpy(state->comm, comm && comm[0] ? comm : parent_state->comm, sizeof(state->comm) - 1);
        return state;
    }

    state->main_pid = pid;
    snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", pid);
    strncpy(state->workspace, workspace_root(), sizeof(state->workspace) - 1);
    strncpy(state->comm,
            comm && comm[0] ? comm : detected_comm,
            sizeof(state->comm) - 1);

    publish_agent_registration(state);
    return state;
}

static struct agent_state *get_or_create_ssl_fallback_agent(const struct probe_SSL_data_t *event)
{
    struct agent_state *state;

    if (!event) {
        return NULL;
    }

    state = find_agent_by_pid(event->pid);
    if (state) {
        if (event->timestamp_ns > state->metrics.last_active_ns) {
            state->metrics.last_active_ns = event->timestamp_ns;
        }
        return state;
    }

    state = allocate_agent_slot();
    if (!state) {
        return NULL;
    }

    state->pid = event->pid;
    state->main_pid = event->pid;
    state->metrics.window_start_ns = event->timestamp_ns;
    state->metrics.last_active_ns = event->timestamp_ns;

    if (event->agent_id != 0) {
        snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", event->agent_id);
    } else {
        snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", event->pid);
    }

    strncpy(state->workspace, workspace_root(), sizeof(state->workspace) - 1);
    state->workspace[sizeof(state->workspace) - 1] = '\0';

    if (event->comm[0]) {
        strncpy(state->comm, event->comm, sizeof(state->comm) - 1);
    } else if (event->agent_name[0]) {
        strncpy(state->comm, event->agent_name, sizeof(state->comm) - 1);
    } else {
        strncpy(state->comm, "ssl", sizeof(state->comm) - 1);
    }
    state->comm[sizeof(state->comm) - 1] = '\0';

    publish_agent_registration(state);
    return state;
}

static void publish_metrics_if_needed(struct agent_state *state, unsigned long long ts_ns)
{
    redisReply *reply;
    char key[128];

    if (!redis_ctx || !state || !state->in_use) {
        return;
    }
    if (state->metrics.window_start_ns == 0) {
        state->metrics.window_start_ns = ts_ns;
        state->metrics.last_active_ns = ts_ns;
        return;
    }
    if (ts_ns - state->metrics.window_start_ns < METRIC_WINDOW_NS) {
        state->metrics.last_active_ns = ts_ns;
        return;
    }

    snprintf(key, sizeof(key), "inter:metric:%s", state->agent_id);
    reply = redisCommand(
        redis_ctx,
        "HSET %s cpu_usage %f memory_usage %f proc_exec_count %u proc_fork_count %u "
        "fs_open_count %u fs_read_count %u fs_write_count %u fs_unlink_count %u "
        "net_connect_count %u api_call_count %u msg_sent_count %u msg_recv_count %u "
        "unique_files_count %u shell_exec_count %u sensitive_file_count %u workspace_violation %u "
        "window_start_ns %llu last_active_ns %llu",
        key,
        state->metrics.cpu_usage,
        state->metrics.memory_usage,
        state->metrics.proc_exec_count,
        state->metrics.proc_fork_count,
        state->metrics.fs_open_count,
        state->metrics.fs_read_count,
        state->metrics.fs_write_count,
        state->metrics.fs_unlink_count,
        state->metrics.net_connect_count,
        state->metrics.api_call_count,
        state->metrics.msg_sent_count,
        state->metrics.msg_recv_count,
        state->metrics.unique_files_count,
        state->metrics.shell_exec_count,
        state->metrics.sensitive_file_count,
        state->metrics.workspace_violation,
        state->metrics.window_start_ns,
        state->metrics.last_active_ns
    );
    finish_redis_command("redisCommand", reply);

    memset(&state->metrics, 0, sizeof(state->metrics));
    state->metrics.window_start_ns = ts_ns;
    state->metrics.last_active_ns = ts_ns;
}

static void update_metrics_for_sys_event(struct agent_state *state, const struct sys_event *event)
{
    const char *path = event->filename;

    if (!state) {
        return;
    }

    switch (event->event_type) {
    case EVENT_EXECVE:
        state->metrics.proc_exec_count++;
        if (strstr(path, "/sh") || strstr(path, "/bash") || strstr(path, "/zsh")) {
            state->metrics.shell_exec_count++;
        }
        break;
    case EVENT_FORK:
        state->metrics.proc_fork_count++;
        break;
    case EVENT_OPEN:
        state->metrics.fs_open_count++;
        remember_unique_file(&state->metrics, path);
        if (path_is_sensitive(path)) {
            state->metrics.sensitive_file_count++;
        }
        break;
    case EVENT_UNLINK:
        state->metrics.fs_unlink_count++;
        remember_unique_file(&state->metrics, path);
        if (path_is_sensitive(path)) {
            state->metrics.sensitive_file_count++;
        }
        if (path_is_workspace_violation(path)) {
            state->metrics.workspace_violation++;
        }
        break;
    case EVENT_CONNECT:
        state->metrics.net_connect_count++;
        state->metrics.api_call_count++;
        break;
    default:
        break;
    }
}

static void update_metrics_for_ssl_event(struct agent_state *state, unsigned int event_type,
                                         const char *data, unsigned int data_len)
{
    if (!state) {
        return;
    }
    if (event_type == EVENT_SSL_READ) {
        state->metrics.fs_read_count++;
        state->metrics.net_recv_count++;
        state->metrics.msg_recv_count++;
    } else if (event_type == EVENT_SSL_WRITE) {
        state->metrics.fs_write_count++;
        state->metrics.net_send_count++;
        state->metrics.msg_sent_count++;
    }
    if (data && data_len > 0) {
        state->metrics.api_call_count++;
    }
}

static void publish_inter_event(struct agent_state *state, const struct sys_event *event)
{
    redisReply *reply;
    char comm[MAX_COMM_LEN * 2];
    char filename[MAX_PATH_LEN * 2];
    char dip[64];
    const char *event_type = event_stream_type(event->event_type);
    const char *subtype = event_stream_subtype(event->event_type);

    if (!redis_ctx || !state) {
        return;
    }

    shell_escape(event->comm, comm, sizeof(comm));
    shell_escape(event->filename, filename, sizeof(filename));

    switch (event->event_type) {
    case EVENT_EXECVE:
    case EVENT_OPEN:
    case EVENT_UNLINK:
    case EVENT_CHMOD:
        reply = redisCommand(
            redis_ctx,
            "XADD inter:events * event_type %s subtype %s timestamp_ns %llu pid %u tid %u comm %s filename %s parent_pid %u agent_id %s",
            event_type, subtype, event->timestamp, event->pid, event->pid, comm, filename, event->child_pid, state->agent_id
        );
        break;
    case EVENT_FORK:
        reply = redisCommand(
            redis_ctx,
            "XADD inter:events * event_type %s subtype %s timestamp_ns %llu pid %u tid %u comm %s parent_pid %u child_pid %u agent_id %s",
            event_type, subtype, event->timestamp, event->pid, event->pid, comm, event->pid, event->child_pid, state->agent_id
        );
        break;
    case EVENT_CONNECT:
        format_ipv4(event->connect.dip, dip, sizeof(dip));
        reply = redisCommand(
            redis_ctx,
            "XADD inter:events * event_type %s subtype %s timestamp_ns %llu pid %u tid %u comm %s family %d daddr %s dport %d agent_id %s",
            event_type, subtype, event->timestamp, event->pid, event->pid, comm, event->connect.family, dip, event->connect.dport, state->agent_id
        );
        break;
    default:
        return;
    }

    finish_redis_command("redisCommand", reply);
}

static void publish_behavior_event(const struct sys_event *event)
{
    char value[2048];
    const char *behavior_name = get_behavior_name(event->event_type);
    redisReply *reply;

    if (!redis_ctx) {
        return;
    }

    if (event->event_type == EVENT_CONNECT) {
        char dip[64];
        format_ipv4(event->connect.dip, dip, sizeof(dip));
        snprintf(
            value,
            sizeof(value),
            "{\"agent_name\":\"%s\",\"agent_no\":%u,\"behavior_name\":\"%s\",\"behavior_no\":%u,\"timestamp\":%llu,"
            "\"operation\":{\"pid\":%u,\"child_pid\":%u,\"comm\":\"%s\",\"dip\":\"%s\",\"dport\":%d}}",
            event->agent_name,
            event->agent_id,
            behavior_name,
            event->event_type,
            event->timestamp,
            event->pid,
            event->child_pid,
            event->comm,
            dip,
            event->connect.dport
        );
    } else {
        snprintf(
            value,
            sizeof(value),
            "{\"agent_name\":\"%s\",\"agent_no\":%u,\"behavior_name\":\"%s\",\"behavior_no\":%u,\"timestamp\":%llu,"
            "\"operation\":{\"pid\":%u,\"child_pid\":%u,\"comm\":\"%s\",\"target_file\":\"%s\"}}",
            event->agent_name,
            event->agent_id,
            behavior_name,
            event->event_type,
            event->timestamp,
            event->pid,
            event->child_pid,
            event->comm,
            event->filename
        );
    }

    reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL_BEHAVIOR, value);
    finish_redis_command("redisCommand", reply);
}

static void publish_message_event(struct agent_state *state, const char *protocol, const char *msg_type,
                                  const char *data, unsigned int bytes, unsigned long long ts_ns,
                                  unsigned int pid, unsigned int tid)
{
    redisReply *reply;
    char escaped_data[MAX_STREAM_DATA];
    char dst_component[MAX_COMPONENT_LEN];
    char msg_id[64];
    char comm[MAX_COMM_LEN * 2];

    if (!redis_ctx || !state) {
        return;
    }

    sanitize_component(protocol, dst_component, sizeof(dst_component));
    if (dst_component[0] == '\0') {
        strncpy(dst_component, "llm_api", sizeof(dst_component) - 1);
        dst_component[sizeof(dst_component) - 1] = '\0';
    }

    snprintf(msg_id, sizeof(msg_id), "msg_%06llu", ++g_message_seq);
    json_escape_bytes(data, bounded_strnlen_local(data, MAX_STREAM_DATA - 1), escaped_data, sizeof(escaped_data));
    shell_escape(state->comm, comm, sizeof(comm));

    reply = redisCommand(
        redis_ctx,
        "XADD inter:messages * msg_id %s src %s dst %s type %s protocol %s timestamp_ns %llu "
        "pid %u tid %u main_pid %u comm %s agent_id %s bytes %u data %s",
        msg_id,
        state->agent_id,
        dst_component,
        msg_type,
        protocol,
        ts_ns,
        pid,
        tid,
        state->main_pid,
        comm,
        state->agent_id,
        bytes,
        escaped_data
    );
    finish_redis_command("redisCommand", reply);

    reply = redisCommand(redis_ctx, "SADD inter:edges %s:%s", state->agent_id, dst_component);
    finish_redis_command("redisCommand", reply);

    reply = redisCommand(
        redis_ctx,
        "HSET inter:edge:%s:%s src %s dst %s type message weight 1 total_messages %u total_bytes %u last_seen_ns %llu",
        state->agent_id,
        dst_component,
        state->agent_id,
        dst_component,
        1U,
        bytes,
        ts_ns
    );
    finish_redis_command("redisCommand", reply);
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
    redisReply *reply;
    char value[2048];
    char escaped_filename[MAX_PATH_LEN * 2];
    char escaped_dip[64];
    struct agent_state *state;

    if (!redis_ctx || !event) {
        return -1;
    }

    state = get_or_create_agent(event->pid, event->child_pid, event->comm, event->timestamp);
    if (state) {
        update_metrics_for_sys_event(state, event);
        publish_metrics_if_needed(state, event->timestamp);
        publish_inter_event(state, event);
    }

    publish_behavior_event(event);

    if (event->event_type == EVENT_CONNECT) {
        format_ipv4(event->connect.dip, escaped_dip, sizeof(escaped_dip));
        snprintf(
            value,
            sizeof(value),
            "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"dip\":\"%s\",\"dport\":%d,\"agent_id\":\"%s\",\"main_pid\":%u}",
            event->event_type,
            event->pid,
            event->child_pid,
            event->uid,
            event->timestamp,
            event->comm,
            escaped_dip,
            event->connect.dport,
            state ? state->agent_id : "",
            state ? state->main_pid : event->pid
        );
    } else {
        json_escape(event->filename, escaped_filename, sizeof(escaped_filename));
        snprintf(
            value,
            sizeof(value),
            "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"filename\":\"%s\",\"agent_id\":\"%s\",\"main_pid\":%u}",
            event->event_type,
            event->pid,
            event->child_pid,
            event->uid,
            event->timestamp,
            event->comm,
            escaped_filename,
            state ? state->agent_id : "",
            state ? state->main_pid : event->pid
        );
    }

    reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, value);
    finish_redis_command("redisCommand", reply);
    return 0;
}

int ship_ssl_event(struct probe_SSL_data_t *event)
{
    redisReply *reply;
    char *b64_data;
    char *value;
    size_t b64_len;
    size_t json_buffer_size;
    uint32_t mapped_event_type;
    const char *behavior_name;
    struct agent_state *state;

    if (!redis_ctx || !event) {
        return -1;
    }
    if (event->buf_size == 0 || event->buf_filled == 0 || event->is_handshake || event->rw == 2) {
        return 0;
    }

    mapped_event_type = (event->rw == 0) ? EVENT_SSL_READ : EVENT_SSL_WRITE;
    behavior_name = get_behavior_name(mapped_event_type);
    b64_len = 4 * ((event->buf_size + 2) / 3) + 1;
    b64_data = malloc(b64_len);
    if (!b64_data) {
        return -1;
    }
    base64_encode((const unsigned char *)event->buf, event->buf_size, b64_data);

    json_buffer_size = b64_len + 1024;
    value = malloc(json_buffer_size);
    if (!value) {
        free(b64_data);
        return -1;
    }

    snprintf(
        value,
        json_buffer_size,
        "{\"agent_name\":\"%s\",\"agent_no\":%u,\"behavior_name\":\"%s\",\"behavior_no\":%u,\"timestamp\":%llu,"
        "\"operation\":{\"pid\":%u,\"tid\":%u,\"comm\":\"%s\",\"payload_bytes\":%u},\"network_payload\":\"%s\"}",
        event->agent_name,
        event->agent_id,
        behavior_name,
        mapped_event_type,
        event->timestamp_ns,
        event->pid,
        event->tid,
        event->comm,
        event->buf_size,
        b64_data
    );

    reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL_BEHAVIOR, value);
    finish_redis_command("redisCommand", reply);

    state = get_or_create_agent(event->pid, event->pid, event->comm, event->timestamp_ns);
    if (!state) {
        state = get_or_create_ssl_fallback_agent(event);
    }
    if (state) {
        char escaped_payload[MAX_STREAM_DATA];
        update_metrics_for_ssl_event(state, mapped_event_type, (const char *)event->buf, event->buf_size);
        publish_metrics_if_needed(state, event->timestamp_ns);
        json_escape_bytes((const char *)event->buf, bounded_strnlen_local((const char *)event->buf, MAX_STREAM_DATA - 1),
                          escaped_payload, sizeof(escaped_payload));
        publish_message_event(
            state,
            "ssl",
            mapped_event_type == EVENT_SSL_WRITE ? "prompt" : "response",
            escaped_payload,
            event->buf_size,
            event->timestamp_ns,
            event->pid,
            event->tid
        );
    }

    if (state) {
        char escaped_payload[MAX_STREAM_DATA];
        char msg_value[2048];

        json_escape_bytes((const char *)event->buf, bounded_strnlen_local((const char *)event->buf, MAX_STREAM_DATA - 1),
                          escaped_payload, sizeof(escaped_payload));
        snprintf(
            msg_value,
            sizeof(msg_value),
            "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"data_len\":%u,\"data\":\"%s\",\"agent_id\":\"%s\",\"main_pid\":%u}",
            mapped_event_type,
            event->pid,
            event->pid,
            event->timestamp_ns,
            event->comm,
            event->buf_size,
            escaped_payload,
            state->agent_id,
            state->main_pid
        );
        reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL, msg_value);
        finish_redis_command("redisCommand", reply);
    }

    free(value);
    free(b64_data);
    return 0;
}

static __u64 get_process_rss_bytes(__u32 pid)
{
    char path[256];
    FILE *f;
    __u64 size, resident, shared, text, lib, data, dt;

    snprintf(path, sizeof(path), "/proc/%u/statm", pid);
    f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    if (fscanf(f, "%llu %llu %llu %llu %llu %llu %llu",
               &size, &resident, &shared, &text, &lib, &data, &dt) != 7) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return resident * 4096;
}

int ship_resource_sample(__u32 level, __u64 target_id, __u64 cpu_ns, __u64 rss_bytes, int num_procs, __u64 cgroup_id)
{
    char value[1024];
    struct timespec ts;
    __u64 current_timestamp_ms;
    __u64 total_rss_kb;
    __u64 total_cpu_ms;
    __u64 cpu_usec;
    redisReply *reply;

    if (!redis_ctx) {
        return -1;
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    current_timestamp_ms = (__u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    total_rss_kb = rss_bytes / 1024;
    total_cpu_ms = cpu_ns / 1000000;
    cpu_usec = cpu_ns / 1000;

    snprintf(
        value,
        sizeof(value),
        "{\"event\":\"RESOURCE_SAMPLE\",\"timestamp\":%llu,\"level\":%u,\"target_pid\":%llu,"
        "\"total_rss_kb\":%llu,\"total_cpu_user_ms\":%llu,\"total_cpu_sys_ms\":0,\"num_processes\":%d,"
        "\"cgroup_memory_bytes\":%llu,\"cgroup_memory_peak_bytes\":%llu,\"cgroup_cpu_usage_usec\":%llu}",
        current_timestamp_ms,
        level,
        target_id,
        total_rss_kb,
        total_cpu_ms,
        num_procs,
        rss_bytes,
        rss_bytes,
        cpu_usec
    );

    reply = redisCommand(redis_ctx, "PUBLISH %s %s", REDIS_CHANNEL_RESOURCE, value);
    finish_redis_command("redisCommand", reply);
    return 0;
}

void fetch_and_ship_resources(int res_fd)
{
    struct res_key key = {0};
    struct res_key next_key;
    struct res_val val;
    struct agent_agg aggs[128];
    int agg_count = 0;
    __u64 sys_cpu_ns = 0;
    __u64 sys_rss_bytes = 0;
    int sys_procs = 0;

    if (!redis_ctx || res_fd < 0) {
        return;
    }

    memset(aggs, 0, sizeof(aggs));

    while (bpf_map_get_next_key(res_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(res_fd, &next_key, &val) == 0) {
            __u32 current_pid = (__u32)next_key.id;
            __u64 real_rss = get_process_rss_bytes(current_pid);
            int found = -1;
            int i;

            ship_resource_sample(RES_LEVEL_PID, next_key.id, val.cpu_time_ns, real_rss, 1, val.cgroup_id);

            for (i = 0; i < agg_count; i++) {
                if (aggs[i].agent_id == val.agent_id) {
                    found = i;
                    break;
                }
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

            sys_cpu_ns += val.cpu_time_ns;
            sys_rss_bytes += real_rss;
            sys_procs += 1;
        }
        key = next_key;
    }

    for (int i = 0; i < agg_count; i++) {
        ship_resource_sample(RES_LEVEL_AGENT, aggs[i].agent_id, aggs[i].total_cpu_ns,
                             aggs[i].total_rss_bytes, aggs[i].num_processes, aggs[i].cgroup_id);
        ship_resource_sample(RES_LEVEL_CGROUP, aggs[i].cgroup_id, aggs[i].total_cpu_ns,
                             aggs[i].total_rss_bytes, aggs[i].num_processes, aggs[i].cgroup_id);
    }

    if (sys_procs > 0) {
        ship_resource_sample(RES_LEVEL_SYS, 0, sys_cpu_ns, sys_rss_bytes, sys_procs, 0);
    }
}
