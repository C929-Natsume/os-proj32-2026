#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "intra_analyzer.h"
#include "intra_audit.h"

#define STATS_BUCKETS 1024
#define MAX_FILE_SAMPLES 8

#define LOOP_WINDOW_NS (30ULL * 1000 * 1000 * 1000)
#define LOOP_ALERT_COOLDOWN_NS (30ULL * 1000 * 1000 * 1000)
#define EVENT_ALERT_COOLDOWN_NS (5ULL * 1000 * 1000 * 1000)

struct pid_stats
{
    __u32 pid;
    __u64 window_start_ns;
    __u64 last_loop_alert_ns;
    __u64 last_sensitive_alert_ns;
    __u64 last_workspace_alert_ns;
    __u64 last_shell_alert_ns;

    __u32 proc_exec_cnt;
    __u32 fs_open_cnt;
    __u32 fs_read_cnt;
    __u32 fs_write_cnt;
    __u32 fs_unlink_cnt;
    __u32 net_connect_cnt;
    __u32 net_send_cnt;
    __u32 net_recv_cnt;

    __u32 unique_files_cnt;
    char unique_files[MAX_FILE_SAMPLES][MAX_FILENAME];

    struct pid_stats *next;
};

static struct pid_stats *g_pid_stats[STATS_BUCKETS];
static char g_workspace_root[MAX_PATH] = "/mnt/e/os2026";
static unsigned long long g_req_seq = 0;

static inline __u32 pid_hash(__u32 pid)
{
    return pid % STATS_BUCKETS;
}

static struct pid_stats *get_pid_stats(__u32 pid, __u64 ts_ns)
{
    __u32 idx = pid_hash(pid);
    struct pid_stats *p = g_pid_stats[idx];

    while (p)
    {
        if (p->pid == pid)
            return p;
        p = p->next;
    }

    p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    p->pid = pid;
    p->window_start_ns = ts_ns;
    p->next = g_pid_stats[idx];
    g_pid_stats[idx] = p;
    return p;
}

static void rotate_window_if_needed(struct pid_stats *s, __u64 ts_ns)
{
    if (!s)
        return;

    if (ts_ns - s->window_start_ns < LOOP_WINDOW_NS)
        return;

    s->window_start_ns = ts_ns;
    s->proc_exec_cnt = 0;
    s->fs_open_cnt = 0;
    s->fs_read_cnt = 0;
    s->fs_write_cnt = 0;
    s->fs_unlink_cnt = 0;
    s->net_connect_cnt = 0;
    s->net_send_cnt = 0;
    s->net_recv_cnt = 0;
    s->unique_files_cnt = 0;
    memset(s->unique_files, 0, sizeof(s->unique_files));
}

static const char *basename_from_path(const char *path)
{
    if (!path || !path[0])
        return "";
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

static int path_starts_with(const char *path, const char *prefix)
{
    size_t n;
    if (!path || !prefix)
        return 0;
    n = strlen(prefix);
    if (n == 0)
        return 0;
    return strncmp(path, prefix, n) == 0;
}

static int path_contains_sensitive_marker(const char *path)
{
    static const char *const markers[] = {
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/var/run/docker.sock",
        "/proc/kcore",
        "/.ssh/",
        "/.aws/credentials",
        "/.kube/config",
        ".env",
    };
    size_t i;

    if (!path || !path[0])
        return 0;

    for (i = 0; i < sizeof(markers) / sizeof(markers[0]); i++)
    {
        if (strstr(path, markers[i]) != NULL)
            return 1;
    }
    return 0;
}

static int is_shell_exec(const char *path)
{
    static const char *const shell_bins[] = {
        "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh"};
    const char *base = basename_from_path(path);
    size_t i;

    for (i = 0; i < sizeof(shell_bins) / sizeof(shell_bins[0]); i++)
    {
        if (strcmp(base, shell_bins[i]) == 0)
            return 1;
    }
    return 0;
}

static void remember_file_sample(struct pid_stats *s, const char *path)
{
    __u32 i;
    if (!s || !path || !path[0])
        return;

    for (i = 0; i < s->unique_files_cnt; i++)
    {
        if (strncmp(s->unique_files[i], path, MAX_FILENAME) == 0)
            return;
    }

    if (s->unique_files_cnt >= MAX_FILE_SAMPLES)
        return;

    snprintf(s->unique_files[s->unique_files_cnt], MAX_FILENAME, "%s", path);
    s->unique_files_cnt++;
}

static void submit_audit_req(const char *rule,
                             const struct event_header *hdr,
                             const char *object,
                             const char *reason,
                             enum audit_severity sev)
{
    struct audit_req req = {
        .req_id = ++g_req_seq,
        .timestamp_ns = hdr->timestamp_ns,
        .pid = hdr->pid,
        .tid = hdr->tid,
        .comm = hdr->comm,
        .rule = rule,
        .object = object && object[0] ? object : "-",
        .reason = reason,
        .severity = sev,
    };
    intra_audit_submit(&req);
}

static void maybe_emit_loop_alert(struct pid_stats *s, const struct event_header *hdr)
{
    __u32 io_cnt;
    __u32 net_cnt;

    if (!s || !hdr)
        return;

    io_cnt = s->fs_read_cnt + s->fs_write_cnt;
    net_cnt = s->net_connect_cnt + s->net_send_cnt + s->net_recv_cnt;

    if (io_cnt < 120 || net_cnt < 120)
        return;

    if (s->unique_files_cnt > 3)
        return;

    if (hdr->timestamp_ns - s->last_loop_alert_ns < LOOP_ALERT_COOLDOWN_NS)
        return;

    s->last_loop_alert_ns = hdr->timestamp_ns;
    submit_audit_req("POSSIBLE_LOGIC_LOOP", hdr, "-",
                     "文件与网络操作高频且文件对象集中，疑似逻辑循环",
                     AUDIT_SEV_MEDIUM);
}

void intra_init(void)
{
    const char *root = getenv("MONITOR_WORKSPACE");
    if (root && root[0])
        snprintf(g_workspace_root, sizeof(g_workspace_root), "%s", root);
    intra_audit_init(g_workspace_root);
}

void intra_on_proc_event(const struct proc_event *e)
{
    struct pid_stats *s;

    if (!e)
        return;

    s = get_pid_stats(e->hdr.pid, e->hdr.timestamp_ns);
    rotate_window_if_needed(s, e->hdr.timestamp_ns);
    if (!s)
        return;

    if (e->hdr.type == PROC_EXEC)
    {
        s->proc_exec_cnt++;
        if (is_shell_exec(e->exec.filename) &&
            e->hdr.timestamp_ns - s->last_shell_alert_ns >= EVENT_ALERT_COOLDOWN_NS)
        {
            s->last_shell_alert_ns = e->hdr.timestamp_ns;
            submit_audit_req("UNEXPECTED_SHELL_EXEC", &e->hdr, e->exec.filename,
                             "智能体相关进程启动了 shell 解释器",
                             AUDIT_SEV_HIGH);
        }
    }
}

static void maybe_sensitive_alert(struct pid_stats *s, const struct event_header *hdr, const char *path, const char *op)
{
    char reason[160];

    if (!s || !hdr || !path)
        return;

    if (!path_contains_sensitive_marker(path))
        return;

    if (hdr->timestamp_ns - s->last_sensitive_alert_ns < EVENT_ALERT_COOLDOWN_NS)
        return;

    s->last_sensitive_alert_ns = hdr->timestamp_ns;
    snprintf(reason, sizeof(reason), "检测到敏感路径%s", op);
    submit_audit_req("SENSITIVE_FILE_ACCESS", hdr, path, reason, AUDIT_SEV_HIGH);
}

static void maybe_workspace_alert(struct pid_stats *s, const struct event_header *hdr, const char *path, const char *op)
{
    char reason[192];

    if (!s || !hdr || !path || !path[0])
        return;

    if (path[0] != '/')
        return;

    if (path_starts_with(path, g_workspace_root))
        return;

    if (path_starts_with(path, "/tmp/") || path_starts_with(path, "/var/tmp/"))
        return;

    if (hdr->timestamp_ns - s->last_workspace_alert_ns < EVENT_ALERT_COOLDOWN_NS)
        return;

    s->last_workspace_alert_ns = hdr->timestamp_ns;
    snprintf(reason, sizeof(reason), "检测到工作区外%s行为", op);
    submit_audit_req("OUT_OF_WORKSPACE_OPERATION", hdr, path, reason, AUDIT_SEV_HIGH);
}

void intra_on_fs_event(const struct fs_event *e)
{
    struct pid_stats *s;

    if (!e)
        return;

    s = get_pid_stats(e->hdr.pid, e->hdr.timestamp_ns);
    rotate_window_if_needed(s, e->hdr.timestamp_ns);
    if (!s)
        return;

    switch (e->hdr.type)
    {
    case FS_OPEN:
        s->fs_open_cnt++;
        remember_file_sample(s, e->open.filename);
        maybe_sensitive_alert(s, &e->hdr, e->open.filename, "打开");
        break;
    case FS_READ:
        s->fs_read_cnt++;
        remember_file_sample(s, e->read.filename);
        maybe_sensitive_alert(s, &e->hdr, e->read.filename, "读取");
        break;
    case FS_WRITE:
        s->fs_write_cnt++;
        remember_file_sample(s, e->write.filename);
        maybe_sensitive_alert(s, &e->hdr, e->write.filename, "写入");
        maybe_workspace_alert(s, &e->hdr, e->write.filename, "写入");
        break;
    case FS_UNLINK:
        s->fs_unlink_cnt++;
        remember_file_sample(s, e->unlink.filename);
        maybe_sensitive_alert(s, &e->hdr, e->unlink.filename, "删除");
        maybe_workspace_alert(s, &e->hdr, e->unlink.filename, "删除");
        break;
    case FS_RMDIR:
        remember_file_sample(s, e->rmdir.dirname);
        maybe_sensitive_alert(s, &e->hdr, e->rmdir.dirname, "移除目录");
        maybe_workspace_alert(s, &e->hdr, e->rmdir.dirname, "移除目录");
        break;
    case FS_RENAME:
        remember_file_sample(s, e->rename.oldname);
        remember_file_sample(s, e->rename.newname);
        maybe_sensitive_alert(s, &e->hdr, e->rename.oldname, "重命名源");
        maybe_sensitive_alert(s, &e->hdr, e->rename.newname, "重命名目标");
        maybe_workspace_alert(s, &e->hdr, e->rename.oldname, "重命名源");
        maybe_workspace_alert(s, &e->hdr, e->rename.newname, "重命名目标");
        break;
    case FS_CHMOD:
        remember_file_sample(s, e->chmod.filename);
        maybe_sensitive_alert(s, &e->hdr, e->chmod.filename, "权限修改");
        break;
    case FS_CREATE:
        remember_file_sample(s, e->create.filename);
        maybe_sensitive_alert(s, &e->hdr, e->create.filename, "创建");
        maybe_workspace_alert(s, &e->hdr, e->create.filename, "创建");
        break;
    default:
        break;
    }

    maybe_emit_loop_alert(s, &e->hdr);
}

void intra_on_net_event(const struct net_event *e)
{
    struct pid_stats *s;

    if (!e)
        return;

    s = get_pid_stats(e->hdr.pid, e->hdr.timestamp_ns);
    rotate_window_if_needed(s, e->hdr.timestamp_ns);
    if (!s)
        return;

    switch (e->hdr.type)
    {
    case NET_CONNECT:
        s->net_connect_cnt++;
        break;
    case NET_SEND:
        s->net_send_cnt++;
        break;
    case NET_RECV:
        s->net_recv_cnt++;
        break;
    default:
        break;
    }

    maybe_emit_loop_alert(s, &e->hdr);
}
