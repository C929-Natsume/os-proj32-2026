#define _GNU_SOURCE
#include <ctype.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../bpf/common.h"

#define REDIS_PORT 6379
#define REDIS_CHANNEL "ebpf_events"
#define REDIS_CMD_MAX 16384
#define REDIS_VALUE_MAX 4096
#define MAX_TRACKED_AGENTS 128
#define MAX_UNIQUE_FILES 64
#define MAX_AGENT_ID_LEN 64
#define MAX_WORKSPACE_LEN 256
#define MAX_COMPONENT_LEN 96
#define MAX_STREAM_DATA 512
#define MAX_CMDLINE_LEN 1024
#define METRIC_WINDOW_NS (30ULL * 1000ULL * 1000ULL * 1000ULL)

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
static const char *g_ignored_markers[] = {
    "ebpf-multi-agent-monitor/src/user/loader",
    "ebpf-multi-agent-monitor/src/user/ringbuf_handler",
    "redis-cli",
    "run_loader.sh",
    "run_ringbuf.sh",
    "run_analyzer.sh",
};
static const char *g_ignored_comms[] = {
    "loader",
    "ringbuf_handler",
    "redis-cli",
};

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
        if (c == '\n' || c == '\r' || c == '\t') {
            dst[di++] = ' ';
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

static void format_ipv4(const char raw[46], char *out, size_t out_len)
{
    const unsigned char *ip = (const unsigned char *)raw;
    if (!out || out_len == 0) {
        return;
    }
    snprintf(out, out_len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
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

static int read_proc_cmdline(unsigned int pid, char *dst, size_t dst_len)
{
    char path[64];
    FILE *fp;
    size_t nread;
    size_t i;

    if (!dst || dst_len == 0) {
        return -1;
    }

    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
    fp = fopen(path, "r");
    if (!fp) {
        dst[0] = '\0';
        return -1;
    }

    nread = fread(dst, 1, dst_len - 1, fp);
    fclose(fp);
    dst[nread] = '\0';

    for (i = 0; i < nread; i++) {
        if (dst[i] == '\0') {
            dst[i] = ' ';
        }
    }

    return nread > 0 ? 0 : -1;
}

static int contains_any_marker(const char *text, const char *const *markers, size_t marker_count)
{
    size_t i;

    if (!text || !text[0]) {
        return 0;
    }

    for (i = 0; i < marker_count; i++) {
        if (markers[i] && strstr(text, markers[i]) != NULL) {
            return 1;
        }
    }

    return 0;
}

static int comm_is_ignored(const char *comm)
{
    size_t i;

    if (!comm || !comm[0]) {
        return 0;
    }

    for (i = 0; i < sizeof(g_ignored_comms) / sizeof(g_ignored_comms[0]); i++) {
        if (strcmp(comm, g_ignored_comms[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static int pid_is_real_agent_root(unsigned int pid, const char *comm)
{
    char cmdline[MAX_CMDLINE_LEN];
    char cmdline_lower[MAX_CMDLINE_LEN];
    char comm_lower[MAX_COMM_LEN];

    if (comm_is_ignored(comm)) {
        return 0;
    }

    if (read_proc_cmdline(pid, cmdline, sizeof(cmdline)) == 0) {
        lowercase_copy(cmdline, cmdline_lower, sizeof(cmdline_lower));
        if (contains_any_marker(
                cmdline_lower, g_ignored_markers, sizeof(g_ignored_markers) / sizeof(g_ignored_markers[0]))) {
            return 0;
        }
        if (contains_any_marker(
                cmdline_lower, g_agent_markers, sizeof(g_agent_markers) / sizeof(g_agent_markers[0]))) {
            return 1;
        }
    }

    lowercase_copy(comm, comm_lower, sizeof(comm_lower));
    return contains_any_marker(comm_lower, g_agent_markers, sizeof(g_agent_markers) / sizeof(g_agent_markers[0]));
}

static int run_ping_check(void)
{
    FILE *fp = popen("redis-cli -p 6379 ping 2>/dev/null", "r");
    char out[64] = {0};

    if (!fp) {
        return -1;
    }
    if (!fgets(out, sizeof(out), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    return strstr(out, "PONG") ? 0 : -1;
}

static void run_redis_command(const char *command)
{
    FILE *fp;

    if (!command || !command[0]) {
        return;
    }

    fp = popen(command, "r");
    if (!fp) {
        fprintf(stderr, "[REDIS] Failed to execute command\n");
        return;
    }
    while (fgetc(fp) != EOF) {
    }
    pclose(fp);
}

static void publish_payload(const char *payload)
{
    FILE *fp;
    char cmd[128];

    if (!payload || !payload[0]) {
        return;
    }

    snprintf(cmd, sizeof(cmd), "redis-cli -p %d -x PUBLISH %s >/dev/null",
             REDIS_PORT, REDIS_CHANNEL);
    fp = popen(cmd, "w");
    if (!fp) {
        fprintf(stderr, "[REDIS] Failed to publish payload\n");
        return;
    }
    fwrite(payload, 1, strlen(payload), fp);
    pclose(fp);
}

static void reset_metrics(struct agent_metrics *metrics, unsigned long long window_start_ns)
{
    if (!metrics) {
        return;
    }
    memset(metrics, 0, sizeof(*metrics));
    metrics->window_start_ns = window_start_ns;
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

static int path_is_outside_workspace(const char *path)
{
    const char *workspace = workspace_root();

    if (!path || !path[0] || path[0] != '/') {
        return 0;
    }
    if (strncmp(path, workspace, strlen(workspace)) == 0) {
        return 0;
    }
    if (strncmp(path, "/tmp/", 5) == 0 || strncmp(path, "/var/tmp/", 9) == 0) {
        return 0;
    }
    return 1;
}

static int path_is_shell(const char *path)
{
    const char *base = strrchr(path ? path : "", '/');
    const char *name = base ? base + 1 : path;
    static const char *shells[] = {"sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh"};
    size_t i;

    if (!name || !name[0]) {
        return 0;
    }
    for (i = 0; i < sizeof(shells) / sizeof(shells[0]); i++) {
        if (strcmp(name, shells[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static void remember_unique_file(struct agent_metrics *metrics, const char *path)
{
    unsigned int i;

    if (!metrics || !path || !path[0]) {
        return;
    }
    for (i = 0; i < metrics->unique_files_count; i++) {
        if (strncmp(metrics->unique_files[i], path, MAX_PATH_LEN) == 0) {
            return;
        }
    }
    if (metrics->unique_files_count >= MAX_UNIQUE_FILES) {
        return;
    }
    strncpy(metrics->unique_files[metrics->unique_files_count], path, MAX_PATH_LEN - 1);
    metrics->unique_files[metrics->unique_files_count][MAX_PATH_LEN - 1] = '\0';
    metrics->unique_files_count++;
}

static void metrics_update_sys(struct agent_state *state, const struct sys_event *event)
{
    struct agent_metrics *metrics;

    if (!state || !event) {
        return;
    }

    metrics = &state->metrics;
    if (metrics->window_start_ns == 0) {
        metrics->window_start_ns = event->timestamp;
    }
    metrics->last_active_ns = event->timestamp;

    switch (event->event_type) {
    case EVENT_EXECVE:
        metrics->proc_exec_count++;
        if (path_is_shell(event->filename)) {
            metrics->shell_exec_count++;
        }
        break;
    case EVENT_FORK:
        metrics->proc_fork_count++;
        break;
    case EVENT_OPEN:
        metrics->fs_open_count++;
        remember_unique_file(metrics, event->filename);
        if (path_is_sensitive(event->filename)) {
            metrics->sensitive_file_count++;
        }
        if (path_is_outside_workspace(event->filename)) {
            metrics->workspace_violation++;
        }
        break;
    case EVENT_UNLINK:
        metrics->fs_unlink_count++;
        remember_unique_file(metrics, event->filename);
        if (path_is_sensitive(event->filename)) {
            metrics->sensitive_file_count++;
        }
        if (path_is_outside_workspace(event->filename)) {
            metrics->workspace_violation++;
        }
        break;
    case EVENT_CONNECT:
        metrics->net_connect_count++;
        break;
    default:
        break;
    }
}

static void metrics_update_ssl(struct agent_state *state, const struct ssl_event *event)
{
    struct agent_metrics *metrics;

    if (!state || !event) {
        return;
    }

    metrics = &state->metrics;
    if (metrics->window_start_ns == 0) {
        metrics->window_start_ns = event->timestamp;
    }
    metrics->last_active_ns = event->timestamp;

    if (event->event_type == EVENT_SSL_READ) {
        metrics->fs_read_count++;
        metrics->net_recv_count++;
        metrics->msg_recv_count++;
    } else if (event->event_type == EVENT_SSL_WRITE) {
        metrics->fs_write_count++;
        metrics->net_send_count++;
        metrics->msg_sent_count++;
    }
    metrics->api_call_count++;
}

static void flush_metrics(struct agent_state *state, unsigned long long now_ns)
{
    char cmd[REDIS_CMD_MAX];
    char agent_id[MAX_AGENT_ID_LEN];

    if (!state || !state->in_use || state->metrics.window_start_ns == 0 || state->pid != state->main_pid) {
        return;
    }

    shell_escape(state->agent_id, agent_id, sizeof(agent_id));
    snprintf(
        cmd,
        sizeof(cmd),
        "redis-cli -p %d HSET inter:metric:%s "
        "cpu_usage %.3f memory_usage %.3f "
        "proc_exec_count %u proc_fork_count %u "
        "fs_open_count %u fs_read_count %u fs_write_count %u fs_unlink_count %u "
        "net_connect_count %u net_send_count %u net_recv_count %u "
        "api_call_count %u msg_sent_count %u msg_recv_count %u "
        "unique_files_count %u shell_exec_count %u sensitive_file_count %u workspace_violation %u "
        "window_start_ns %llu last_active_ns %llu >/dev/null",
        REDIS_PORT,
        agent_id,
        state->metrics.cpu_usage,
        state->metrics.memory_usage,
        state->metrics.proc_exec_count,
        state->metrics.proc_fork_count,
        state->metrics.fs_open_count,
        state->metrics.fs_read_count,
        state->metrics.fs_write_count,
        state->metrics.fs_unlink_count,
        state->metrics.net_connect_count,
        state->metrics.net_send_count,
        state->metrics.net_recv_count,
        state->metrics.api_call_count,
        state->metrics.msg_sent_count,
        state->metrics.msg_recv_count,
        state->metrics.unique_files_count,
        state->metrics.shell_exec_count,
        state->metrics.sensitive_file_count,
        state->metrics.workspace_violation,
        state->metrics.window_start_ns,
        state->metrics.last_active_ns ? state->metrics.last_active_ns : now_ns);
    run_redis_command(cmd);
    reset_metrics(&state->metrics, now_ns);
}

static void rotate_metrics_if_needed(struct agent_state *state, unsigned long long now_ns)
{
    if (!state || !state->in_use || state->metrics.window_start_ns == 0) {
        return;
    }
    if (now_ns - state->metrics.window_start_ns >= METRIC_WINDOW_NS) {
        flush_metrics(state, now_ns);
    }
}

static struct agent_state *find_agent_by_pid(unsigned int pid)
{
    int i;

    for (i = 0; i < MAX_TRACKED_AGENTS; i++) {
        if (g_agents[i].in_use && g_agents[i].pid == pid) {
            return &g_agents[i];
        }
    }
    return NULL;
}

static struct agent_state *find_agent_root(const struct agent_state *state)
{
    if (!state) {
        return NULL;
    }
    return find_agent_by_pid(state->main_pid);
}

static void register_agent(struct agent_state *state)
{
    char cmd[REDIS_CMD_MAX];
    char agent_id[MAX_AGENT_ID_LEN];
    char comm[MAX_COMM_LEN * 2];
    char workspace[MAX_WORKSPACE_LEN * 2];

    if (!state) {
        return;
    }

    shell_escape(state->agent_id, agent_id, sizeof(agent_id));
    shell_escape(state->comm, comm, sizeof(comm));
    shell_escape(state->workspace, workspace, sizeof(workspace));

    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d SADD inter:agents \"%s\" >/dev/null",
             REDIS_PORT, agent_id);
    run_redis_command(cmd);

    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d HSET inter:agent:%s "
             "agent_id \"%s\" main_pid %u comm \"%s\" workspace \"%s\" status active group default >/dev/null",
             REDIS_PORT, agent_id, agent_id, state->main_pid, comm, workspace);
    run_redis_command(cmd);
}

static struct agent_state *allocate_agent_slot(void)
{
    int i;

    for (i = 0; i < MAX_TRACKED_AGENTS; i++) {
        if (!g_agents[i].in_use) {
            memset(&g_agents[i], 0, sizeof(g_agents[i]));
            g_agents[i].in_use = 1;
            return &g_agents[i];
        }
    }

    return NULL;
}

static struct agent_state *get_or_create_agent(unsigned int pid, unsigned int ppid,
                                               const char *comm, unsigned long long ts_ns)
{
    struct agent_state *state = find_agent_by_pid(pid);
    struct agent_state *parent_state;

    if (state) {
        if (comm && comm[0]) {
            strncpy(state->comm, comm, sizeof(state->comm) - 1);
            state->comm[sizeof(state->comm) - 1] = '\0';
        }
        rotate_metrics_if_needed(find_agent_root(state), ts_ns);
        return state;
    }

    parent_state = find_agent_by_pid(ppid);
    if (parent_state) {
        state = allocate_agent_slot();
        if (!state) {
            return NULL;
        }
        state->pid = pid;
        state->main_pid = parent_state->main_pid;
        strncpy(state->agent_id, parent_state->agent_id, sizeof(state->agent_id) - 1);
        strncpy(state->workspace, parent_state->workspace, sizeof(state->workspace) - 1);
        if (comm && comm[0]) {
            strncpy(state->comm, comm, sizeof(state->comm) - 1);
        }
        return state;
    }

    if (!pid_is_real_agent_root(pid, comm)) {
        return NULL;
    }

    state = allocate_agent_slot();
    if (!state) {
        return NULL;
    }

    state->pid = pid;
    state->main_pid = pid;
    snprintf(state->agent_id, sizeof(state->agent_id), "agent_%u", pid);
    strncpy(state->workspace, workspace_root(), sizeof(state->workspace) - 1);
    if (comm && comm[0]) {
        strncpy(state->comm, comm, sizeof(state->comm) - 1);
    }
    reset_metrics(&state->metrics, ts_ns);
    register_agent(state);
    return state;
}

static void stream_sys_event(const struct agent_state *state, const struct sys_event *event)
{
    char cmd[REDIS_CMD_MAX];
    char subtype[32];
    char comm[MAX_COMM_LEN * 2];
    char filename[MAX_PATH_LEN * 2];
    char dip[32];
    const char *event_type = "proc";

    if (!state || !event) {
        return;
    }

    shell_escape(event->comm, comm, sizeof(comm));
    shell_escape(event->filename, filename, sizeof(filename));

    switch (event->event_type) {
    case EVENT_EXECVE:
        strcpy(subtype, "PROC_EXEC");
        event_type = "proc";
        snprintf(cmd, sizeof(cmd),
                 "redis-cli -p %d XADD inter:events '*' "
                 "event_type \"%s\" subtype \"%s\" timestamp_ns %llu pid %u tid %u comm \"%s\" filename \"%s\" parent_pid %u agent_id \"%s\" >/dev/null",
                 REDIS_PORT, event_type, subtype, (unsigned long long)event->timestamp,
                 event->pid, event->pid, comm, filename, event->ppid, state->agent_id);
        break;
    case EVENT_FORK:
        strcpy(subtype, "PROC_FORK");
        event_type = "proc";
        snprintf(cmd, sizeof(cmd),
                 "redis-cli -p %d XADD inter:events '*' "
                 "event_type \"%s\" subtype \"%s\" timestamp_ns %llu pid %u tid %u comm \"%s\" parent_pid %u child_pid 0 agent_id \"%s\" >/dev/null",
                 REDIS_PORT, event_type, subtype, (unsigned long long)event->timestamp,
                 event->pid, event->pid, comm, event->ppid, state->agent_id);
        break;
    case EVENT_OPEN:
        strcpy(subtype, "FS_OPEN");
        event_type = "fs";
        snprintf(cmd, sizeof(cmd),
                 "redis-cli -p %d XADD inter:events '*' "
                 "event_type \"%s\" subtype \"%s\" timestamp_ns %llu pid %u tid %u comm \"%s\" filename \"%s\" flags 0 agent_id \"%s\" >/dev/null",
                 REDIS_PORT, event_type, subtype, (unsigned long long)event->timestamp,
                 event->pid, event->pid, comm, filename, state->agent_id);
        break;
    case EVENT_UNLINK:
        strcpy(subtype, "FS_UNLINK");
        event_type = "fs";
        snprintf(cmd, sizeof(cmd),
                 "redis-cli -p %d XADD inter:events '*' "
                 "event_type \"%s\" subtype \"%s\" timestamp_ns %llu pid %u tid %u comm \"%s\" filename \"%s\" agent_id \"%s\" >/dev/null",
                 REDIS_PORT, event_type, subtype, (unsigned long long)event->timestamp,
                 event->pid, event->pid, comm, filename, state->agent_id);
        break;
    case EVENT_CONNECT:
        strcpy(subtype, "NET_CONNECT");
        event_type = "net";
        format_ipv4(event->connect.dip, dip, sizeof(dip));
        snprintf(cmd, sizeof(cmd),
                 "redis-cli -p %d XADD inter:events '*' "
                 "event_type \"%s\" subtype \"%s\" timestamp_ns %llu pid %u tid %u comm \"%s\" family %d daddr \"%s\" dport %d agent_id \"%s\" >/dev/null",
                 REDIS_PORT, event_type, subtype, (unsigned long long)event->timestamp,
                 event->pid, event->pid, comm, event->connect.family, dip, event->connect.dport, state->agent_id);
        break;
    default:
        return;
    }

    run_redis_command(cmd);
}

static void stream_ssl_event(const struct agent_state *state, const struct ssl_event *event, const char *escaped_data)
{
    char cmd[REDIS_CMD_MAX];
    char comm[MAX_COMM_LEN * 2];
    const char *subtype = (event->event_type == EVENT_SSL_READ) ? "NET_RECV" : "NET_SEND";

    if (!state || !event) {
        return;
    }

    shell_escape(event->comm, comm, sizeof(comm));
    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d XADD inter:events '*' "
             "event_type net subtype \"%s\" timestamp_ns %llu pid %u tid %u comm \"%s\" bytes %u data \"%s\" agent_id \"%s\" >/dev/null",
             REDIS_PORT, subtype, (unsigned long long)event->timestamp,
             event->pid, event->pid, comm, event->data_len, escaped_data ? escaped_data : "", state->agent_id);
    run_redis_command(cmd);
}

static void ship_edge(const struct agent_state *state, const char *dst, const char *type,
                      unsigned int bytes, unsigned long long ts_ns)
{
    char cmd[REDIS_CMD_MAX];
    char dst_component[MAX_COMPONENT_LEN];

    if (!state || !dst || !type) {
        return;
    }

    sanitize_component(dst, dst_component, sizeof(dst_component));
    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d SADD inter:edges \"%s:%s\" >/dev/null",
             REDIS_PORT, state->agent_id, dst_component);
    run_redis_command(cmd);

    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d HSETNX inter:edge:%s:%s first_seen_ns %llu >/dev/null",
             REDIS_PORT, state->agent_id, dst_component, ts_ns);
    run_redis_command(cmd);

    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d HSET inter:edge:%s:%s src \"%s\" dst \"%s\" type \"%s\" weight 1 last_seen_ns %llu >/dev/null",
             REDIS_PORT, state->agent_id, dst_component, state->agent_id, dst_component, type, ts_ns);
    run_redis_command(cmd);

    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d HINCRBY inter:edge:%s:%s total_messages 1 >/dev/null",
             REDIS_PORT, state->agent_id, dst_component);
    run_redis_command(cmd);

    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d HINCRBY inter:edge:%s:%s total_bytes %u >/dev/null",
             REDIS_PORT, state->agent_id, dst_component, bytes);
    run_redis_command(cmd);
}

static void ship_message(const struct agent_state *state, const char *dst, const char *msg_type,
                         const char *protocol, unsigned int bytes, unsigned int dst_port,
                         unsigned long long ts_ns)
{
    char cmd[REDIS_CMD_MAX];
    char dst_component[MAX_COMPONENT_LEN];
    char msg_id[64];

    if (!state || !dst || !msg_type || !protocol) {
        return;
    }

    sanitize_component(dst, dst_component, sizeof(dst_component));
    g_message_seq++;
    snprintf(msg_id, sizeof(msg_id), "msg_%06llu", g_message_seq);

    snprintf(cmd, sizeof(cmd),
             "redis-cli -p %d XADD inter:messages '*' "
             "msg_id \"%s\" src_agent \"%s\" dst_agent \"%s\" msg_type \"%s\" protocol \"%s\" "
             "data_size %u timestamp_ns %llu src_pid %u dst_pid 0 src_port 0 dst_port %u status_code 0 latency_us 0 >/dev/null",
             REDIS_PORT, msg_id, state->agent_id, dst_component, msg_type, protocol,
             bytes, ts_ns, state->pid, dst_port);
    run_redis_command(cmd);
}

int redis_shipper_init(void)
{
    printf("[REDIS] Checking Redis at 127.0.0.1:%d...\n", REDIS_PORT);
    if (run_ping_check() != 0) {
        fprintf(stderr, "[REDIS] Redis ping failed. Make sure redis-server is running.\n");
        return -1;
    }
    printf("[REDIS] Redis is reachable.\n");
    return 0;
}

void redis_shipper_close(void)
{
    int i;

    for (i = 0; i < MAX_TRACKED_AGENTS; i++) {
        if (g_agents[i].in_use) {
            flush_metrics(&g_agents[i], g_agents[i].metrics.last_active_ns);
        }
    }
}

int ship_sys_event(struct sys_event *event)
{
    char value[REDIS_VALUE_MAX];
    char dip[32];
    char comm_json[MAX_COMM_LEN * 2];
    char filename_json[MAX_PATH_LEN * 2];
    struct agent_state *state;
    char dst_key[MAX_COMPONENT_LEN];
    const char *protocol;

    if (!event) {
        return -1;
    }

    state = get_or_create_agent(event->pid, event->ppid, event->comm, event->timestamp);
    if (!state) {
        return 0;
    }

    if (event->event_type == EVENT_CONNECT) {
        format_ipv4(event->connect.dip, dip, sizeof(dip));
        json_escape(event->comm, comm_json, sizeof(comm_json));
        snprintf(value, sizeof(value),
                 "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"dip\":\"%s\",\"dport\":%d,\"agent_id\":\"%s\",\"main_pid\":%u}",
                 event->event_type, event->pid, event->ppid, event->uid,
                 (unsigned long long)event->timestamp, comm_json, dip, event->connect.dport,
                 state->agent_id, state->main_pid);
    } else {
        json_escape(event->comm, comm_json, sizeof(comm_json));
        json_escape(event->filename, filename_json, sizeof(filename_json));
        snprintf(value, sizeof(value),
                 "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"filename\":\"%s\",\"agent_id\":\"%s\",\"main_pid\":%u}",
                 event->event_type, event->pid, event->ppid, event->uid,
                 (unsigned long long)event->timestamp, comm_json, filename_json,
                 state->agent_id, state->main_pid);
    }
    publish_payload(value);

    metrics_update_sys(find_agent_root(state), event);
    stream_sys_event(state, event);

    if (event->event_type == EVENT_CONNECT) {
        snprintf(dst_key, sizeof(dst_key), "external_%s_%d", dip, event->connect.dport);
        protocol = (event->connect.dport == 80 || event->connect.dport == 443) ? "HTTP" : "TCP";
        ship_edge(state, dst_key, "api_call", 0, event->timestamp);
        ship_message(state, dst_key, "request", protocol, 0, event->connect.dport, event->timestamp);
    }

    return 0;
}

int ship_ssl_event(struct ssl_event *event)
{
    char value[REDIS_CMD_MAX];
    char preview[2048];
    char preview_json[2048];
    char comm_json[MAX_COMM_LEN * 2];
    size_t preview_len;
    struct agent_state *state;
    char dst_key[MAX_COMPONENT_LEN];

    if (!event) {
        return -1;
    }

    state = get_or_create_agent(event->pid, event->ppid, event->comm, event->timestamp);
    if (!state) {
        return 0;
    }

    preview_len = event->data_len;
    if (preview_len > MAX_STREAM_DATA) {
        preview_len = MAX_STREAM_DATA;
    }
    preview_len = bounded_strnlen_local(event->data, preview_len);
    shell_escape_bytes(event->data, preview_len, preview, sizeof(preview));
    json_escape_bytes(event->data, preview_len, preview_json, sizeof(preview_json));
    json_escape(event->comm, comm_json, sizeof(comm_json));

    snprintf(value, sizeof(value),
             "{\"type\":%u,\"pid\":%u,\"ppid\":%u,\"timestamp\":%llu,\"comm\":\"%s\",\"data_len\":%u,\"data\":\"%s\",\"agent_id\":\"%s\",\"main_pid\":%u}",
             event->event_type, event->pid, event->ppid,
             (unsigned long long)event->timestamp, comm_json, event->data_len, preview_json,
             state->agent_id, state->main_pid);
    publish_payload(value);

    metrics_update_ssl(find_agent_root(state), event);
    stream_ssl_event(state, event, preview);

    snprintf(dst_key, sizeof(dst_key), "external_ssl_%u", event->pid);
    ship_edge(state, dst_key, "message", event->data_len, event->timestamp);
    ship_message(
        state,
        dst_key,
        (event->event_type == EVENT_SSL_READ) ? "response" : "request",
        "HTTP",
        event->data_len,
        443,
        event->timestamp);

    return 0;
}
