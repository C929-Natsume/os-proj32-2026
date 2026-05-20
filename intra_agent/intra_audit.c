#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "intra_audit.h"

#define MAX_RULE_ITEMS 64
#define MAX_LINE_LEN 2048

enum audit_class
{
    AUDIT_CLASS_WHITE = 1,
    AUDIT_CLASS_BLACK = 2,
    AUDIT_CLASS_GRAY = 3,
};

enum llm_decision
{
    LLM_DECISION_CONFIRM = 1,
    LLM_DECISION_SUPPRESS = 2,
    LLM_DECISION_UNKNOWN = 3,
};

static char g_workspace_root[MAX_PATH] = "/mnt/e/os2026";
static const char *g_llm_cmd = NULL;
static char *g_white_path_prefixes[MAX_RULE_ITEMS];
static int g_white_path_prefix_cnt = 0;
static char *g_black_path_markers[MAX_RULE_ITEMS];
static int g_black_path_marker_cnt = 0;
static char *g_white_rules[MAX_RULE_ITEMS];
static int g_white_rule_cnt = 0;
static char *g_black_rules[MAX_RULE_ITEMS];
static int g_black_rule_cnt = 0;
static char *g_gray_rules[MAX_RULE_ITEMS];
static int g_gray_rule_cnt = 0;
static char *g_llm_allow_suppress_rules[MAX_RULE_ITEMS];
static int g_llm_allow_suppress_rule_cnt = 0;
static char g_rule_file[MAX_PATH];
static long long g_rule_file_mtime = -1;
static unsigned long long g_last_reload_check_ns = 0;

static char *xstrdup(const char *s)
{
    size_t n;
    char *p;
    if (!s)
        return NULL;
    n = strlen(s) + 1;
    p = malloc(n);
    if (!p)
        return NULL;
    memcpy(p, s, n);
    return p;
}

static char *trim_spaces(char *s)
{
    char *end;
    while (*s == ' ' || *s == '\t')
        s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = '\0';
    return s;
}

static int add_item(char **arr, int *cnt, const char *item)
{
    char *dup;
    if (!arr || !cnt || !item || !item[0])
        return -1;
    if (*cnt >= MAX_RULE_ITEMS)
        return -1;
    dup = xstrdup(item);
    if (!dup)
        return -1;
    arr[*cnt] = dup;
    (*cnt)++;
    return 0;
}

static void free_list(char **arr, int *cnt)
{
    int i;
    if (!arr || !cnt)
        return;
    for (i = 0; i < *cnt; i++)
    {
        free(arr[i]);
        arr[i] = NULL;
    }
    *cnt = 0;
}

static void clear_all_rules(void)
{
    free_list(g_white_path_prefixes, &g_white_path_prefix_cnt);
    free_list(g_black_path_markers, &g_black_path_marker_cnt);
    free_list(g_white_rules, &g_white_rule_cnt);
    free_list(g_black_rules, &g_black_rule_cnt);
    free_list(g_gray_rules, &g_gray_rule_cnt);
    free_list(g_llm_allow_suppress_rules, &g_llm_allow_suppress_rule_cnt);
}

static void parse_csv(char *value, char **arr, int *cnt)
{
    char *tok;
    char *saveptr = NULL;
    if (!value)
        return;
    for (tok = strtok_r(value, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr))
    {
        char *t = trim_spaces(tok);
        if (t[0])
            add_item(arr, cnt, t);
    }
}

static int in_list(const char *s, char **arr, int cnt)
{
    int i;
    if (!s)
        return 0;
    for (i = 0; i < cnt; i++)
    {
        if (arr[i] && strcmp(arr[i], s) == 0)
            return 1;
    }
    return 0;
}

static const char *class_name(enum audit_class c)
{
    switch (c)
    {
    case AUDIT_CLASS_WHITE:
        return "WHITE";
    case AUDIT_CLASS_BLACK:
        return "BLACK";
    default:
        return "GRAY";
    }
}

static const char *severity_name(enum audit_severity sev)
{
    switch (sev)
    {
    case AUDIT_SEV_HIGH:
        return "HIGH";
    case AUDIT_SEV_MEDIUM:
        return "MEDIUM";
    default:
        return "LOW";
    }
}

static int path_is_workspace_or_temp(const char *path)
{
    int i;
    if (!path || !path[0])
        return 1;
    for (i = 0; i < g_white_path_prefix_cnt; i++)
    {
        size_t n = strlen(g_white_path_prefixes[i]);
        if (n > 0 && strncmp(path, g_white_path_prefixes[i], n) == 0)
            return 1;
    }
    return 0;
}

static int path_matches_black_marker(const char *path)
{
    int i;
    if (!path)
        return 0;
    for (i = 0; i < g_black_path_marker_cnt; i++)
    {
        if (g_black_path_markers[i] && strstr(path, g_black_path_markers[i]) != NULL)
            return 1;
    }
    return 0;
}

static void load_default_rules(void)
{
    add_item(g_white_path_prefixes, &g_white_path_prefix_cnt, g_workspace_root);
    add_item(g_white_path_prefixes, &g_white_path_prefix_cnt, "/tmp/");
    add_item(g_white_path_prefixes, &g_white_path_prefix_cnt, "/var/tmp/");

    add_item(g_black_path_markers, &g_black_path_marker_cnt, "/etc/shadow");
    add_item(g_black_path_markers, &g_black_path_marker_cnt, "/etc/passwd");
    add_item(g_black_path_markers, &g_black_path_marker_cnt, "/etc/sudoers");
    add_item(g_black_path_markers, &g_black_path_marker_cnt, "/var/run/docker.sock");
    add_item(g_black_path_markers, &g_black_path_marker_cnt, "/.ssh/");
    add_item(g_black_path_markers, &g_black_path_marker_cnt, "/.aws/credentials");
    add_item(g_black_path_markers, &g_black_path_marker_cnt, "/.kube/config");
    add_item(g_black_path_markers, &g_black_path_marker_cnt, ".env");

    add_item(g_black_rules, &g_black_rule_cnt, "UNEXPECTED_SHELL_EXEC");
    add_item(g_black_rules, &g_black_rule_cnt, "SENSITIVE_FILE_ACCESS");
    add_item(g_black_rules, &g_black_rule_cnt, "OUT_OF_WORKSPACE_OPERATION");

    add_item(g_gray_rules, &g_gray_rule_cnt, "POSSIBLE_LOGIC_LOOP");

    /* secure-by-default: high-risk black events are NOT suppressible by LLM
     * unless explicitly configured in llm_allow_suppress_rules
     */
}

static void load_rule_file(const char *path)
{
    FILE *f;
    char line[MAX_LINE_LEN];

    if (!path || !path[0])
        return;
    f = fopen(path, "r");
    if (!f)
        return;

    while (fgets(line, sizeof(line), f))
    {
        char *eq;
        char *key;
        char *value;
        key = trim_spaces(line);
        if (!key[0] || key[0] == '#')
            continue;

        eq = strchr(key, '=');
        if (!eq)
            continue;
        *eq = '\0';
        value = trim_spaces(eq + 1);
        key = trim_spaces(key);

        if (strcmp(key, "white_path_prefixes") == 0)
            parse_csv(value, g_white_path_prefixes, &g_white_path_prefix_cnt);
        else if (strcmp(key, "black_path_markers") == 0)
            parse_csv(value, g_black_path_markers, &g_black_path_marker_cnt);
        else if (strcmp(key, "white_rules") == 0)
            parse_csv(value, g_white_rules, &g_white_rule_cnt);
        else if (strcmp(key, "black_rules") == 0)
            parse_csv(value, g_black_rules, &g_black_rule_cnt);
        else if (strcmp(key, "gray_rules") == 0)
            parse_csv(value, g_gray_rules, &g_gray_rule_cnt);
        else if (strcmp(key, "llm_allow_suppress_rules") == 0)
            parse_csv(value, g_llm_allow_suppress_rules, &g_llm_allow_suppress_rule_cnt);
    }
    fclose(f);
}

static void reload_rules_from_files(void)
{
    clear_all_rules();
    load_default_rules();
    if (g_rule_file[0])
        load_rule_file(g_rule_file);
}

static void maybe_reload_rules(__u64 ts_ns)
{
    struct stat st;
    const __u64 interval_ns = 5ULL * 1000 * 1000 * 1000;

    if (!g_rule_file[0])
        return;

    if (g_last_reload_check_ns != 0 && ts_ns - g_last_reload_check_ns < interval_ns)
        return;
    g_last_reload_check_ns = ts_ns;

    if (stat(g_rule_file, &st) != 0)
        return;

    if (g_rule_file_mtime == (long long)st.st_mtime)
        return;

    g_rule_file_mtime = (long long)st.st_mtime;
    reload_rules_from_files();
    printf("[请求][单体审计] phase=config class=GRAY id=0 ts_ns=%llu pid=0 tid=0 comm=- sev=LOW rule=RULES_RELOAD object=%s reason=规则文件已重载 note=热更新\n",
           (unsigned long long)ts_ns, g_rule_file);
}

static enum audit_class classify_req(const struct audit_req *req)
{
    if (!req)
        return AUDIT_CLASS_GRAY;

    if (in_list(req->rule, g_white_rules, g_white_rule_cnt))
        return AUDIT_CLASS_WHITE;

    if (in_list(req->rule, g_black_rules, g_black_rule_cnt))
        return AUDIT_CLASS_BLACK;

    if (in_list(req->rule, g_gray_rules, g_gray_rule_cnt))
        return AUDIT_CLASS_GRAY;

    if (req->severity == AUDIT_SEV_HIGH)
        return AUDIT_CLASS_BLACK;

    if (req->object && path_is_workspace_or_temp(req->object))
        return AUDIT_CLASS_WHITE;

    if (path_matches_black_marker(req->object))
        return AUDIT_CLASS_BLACK;

    return AUDIT_CLASS_GRAY;
}

static void emit_req_log(const char *phase, enum audit_class c, const struct audit_req *req, const char *note)
{
    printf("[请求][单体审计] phase=%s class=%s id=%llu ts_ns=%llu pid=%u tid=%u comm=%s sev=%s rule=%s object=%s reason=%s note=%s\n",
           phase,
           class_name(c),
           req->req_id,
           (unsigned long long)req->timestamp_ns,
           req->pid,
           req->tid,
           req->comm ? req->comm : "-",
           severity_name(req->severity),
           req->rule ? req->rule : "-",
           req->object && req->object[0] ? req->object : "-",
           req->reason ? req->reason : "-",
           note ? note : "-");
}

static void emit_alert_log(const struct audit_req *req, const char *note)
{
    printf("[告警][单体审计][%s] ts_ns=%llu pid=%u tid=%u comm=%s object=%s reason=%s note=%s\n",
           req->rule ? req->rule : "UNKNOWN",
           (unsigned long long)req->timestamp_ns,
           req->pid,
           req->tid,
           req->comm ? req->comm : "-",
           req->object && req->object[0] ? req->object : "-",
           req->reason ? req->reason : "-",
           note ? note : "-");
}

static void shell_quote(const char *src, char *dst, size_t cap)
{
    size_t i = 0;
    if (cap == 0)
        return;
    dst[i++] = '\'';
    while (src && *src && i + 4 < cap)
    {
        if (*src == '\'')
        {
            dst[i++] = '\'';
            dst[i++] = '\\';
            dst[i++] = '\'';
            dst[i++] = '\'';
        }
        else
        {
            dst[i++] = *src;
        }
        src++;
    }
    if (i + 1 < cap)
        dst[i++] = '\'';
    dst[i] = '\0';
}

static enum llm_decision llm_review(const struct audit_req *req)
{
    char prompt[1024];
    char escaped[2200];
    char cmdline[2600];
    char out[64];
    FILE *fp;

    if (!g_llm_cmd || !g_llm_cmd[0])
        return LLM_DECISION_UNKNOWN;

    snprintf(prompt, sizeof(prompt),
             "You are security judge. Return only one token: CONFIRM or SUPPRESS or UNSURE. "
             "rule=%s; reason=%s; object=%s; pid=%u; comm=%s",
             req->rule ? req->rule : "-",
             req->reason ? req->reason : "-",
             req->object ? req->object : "-",
             req->pid,
             req->comm ? req->comm : "-");
    shell_quote(prompt, escaped, sizeof(escaped));
    snprintf(cmdline, sizeof(cmdline), "%s %s", g_llm_cmd, escaped);

    fp = popen(cmdline, "r");
    if (!fp)
        return LLM_DECISION_UNKNOWN;
    if (!fgets(out, sizeof(out), fp))
    {
        pclose(fp);
        return LLM_DECISION_UNKNOWN;
    }
    pclose(fp);

    if (strstr(out, "CONFIRM"))
        return LLM_DECISION_CONFIRM;
    if (strstr(out, "SUPPRESS"))
        return LLM_DECISION_SUPPRESS;
    return LLM_DECISION_UNKNOWN;
}

static int llm_suppress_allowed(const struct audit_req *req)
{
    if (!req || !req->rule)
        return 0;
    return in_list(req->rule, g_llm_allow_suppress_rules, g_llm_allow_suppress_rule_cnt);
}

void intra_audit_init(const char *workspace_root)
{
    char default_rule_path[MAX_PATH];
    const char *rule_file = getenv("MONITOR_AUDIT_RULES");
    const char *cmd = getenv("MONITOR_LLM_JUDGE_CMD");
    if (workspace_root && workspace_root[0])
        snprintf(g_workspace_root, sizeof(g_workspace_root), "%s", workspace_root);
    if (cmd && cmd[0])
        g_llm_cmd = cmd;

    if (!rule_file || !rule_file[0])
    {
        size_t need = strlen(g_workspace_root) + strlen("/intra_agent/audit_rules.conf") + 1;
        if (need < sizeof(default_rule_path))
        {
            default_rule_path[0] = '\0';
            strcat(default_rule_path, g_workspace_root);
            strcat(default_rule_path, "/intra_agent/audit_rules.conf");
            rule_file = default_rule_path;
        }
    }
    g_rule_file[0] = '\0';
    if (rule_file && rule_file[0])
        snprintf(g_rule_file, sizeof(g_rule_file), "%s", rule_file);
    reload_rules_from_files();

    if (g_rule_file[0])
    {
        struct stat st;
        if (stat(g_rule_file, &st) == 0)
            g_rule_file_mtime = (long long)st.st_mtime;
    }
}

void intra_audit_submit(const struct audit_req *req)
{
    enum audit_class c;
    enum llm_decision d;

    if (!req)
        return;

    maybe_reload_rules(req->timestamp_ns);
    c = classify_req(req);
    emit_req_log("audit", c, req, "已进入审计流程");

    if (c == AUDIT_CLASS_WHITE)
    {
        emit_req_log("result", c, req, "白名单放行");
        return;
    }

    if (c == AUDIT_CLASS_GRAY)
    {
        emit_req_log("result", c, req, "灰名单待关联分析");
        if (req->severity >= AUDIT_SEV_MEDIUM)
            emit_alert_log(req, "灰名单高优先级提醒");
        return;
    }

    d = llm_review(req);
    if (d == LLM_DECISION_SUPPRESS)
    {
        if (llm_suppress_allowed(req))
        {
            emit_req_log("llm", c, req, "LLM判定抑制告警");
            return;
        }
        emit_req_log("llm", c, req, "策略阻断抑制请求");
        emit_alert_log(req, "黑名单策略强制告警");
        return;
    }
    if (d == LLM_DECISION_CONFIRM)
    {
        emit_req_log("llm", c, req, "LLM确认风险");
        emit_alert_log(req, "黑名单确认告警");
        return;
    }

    emit_req_log("llm", c, req, "LLM不可用或不确定");
    emit_alert_log(req, "黑名单兜底告警");
}
