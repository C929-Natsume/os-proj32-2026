#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <hiredis/hiredis.h>
#include "../bpf/common.h"
#include "metrics_aggregator.h"
#include "redis_client.h"

struct agent_agg {
    __u32 agent_id;
    __u64 total_cpu_ns;
    __u64 total_rss_bytes;
    int num_processes;
    __u64 cgroup_id;
};

static unsigned long long read_process_cpu_ticks(__u32 pid)
{
    char path[256], buf[4096], *p, *saveptr = NULL, *token;
    FILE *f;
    int i;
    unsigned long long utime = 0, stime = 0;

    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);

    p = strrchr(buf, ')');
    if (!p) return 0;
    p += 2;

    for (i = 0; i < 12; i++) {
        token = strtok_r(i == 0 ? p : NULL, " ", &saveptr);
        if (!token) return 0;
        if (i == 11) utime = strtoull(token, NULL, 10);
    }
    token = strtok_r(NULL, " ", &saveptr);
    if (!token) return 0;
    stime = strtoull(token, NULL, 10);
    return utime + stime;
}

static __u64 read_total_memory_bytes(void)
{
    static __u64 cached = 0;
    FILE *f;
    char buf[256];
    if (cached != 0) return cached;
    f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    while (fgets(buf, sizeof(buf), f)) {
        unsigned long long kb;
        if (sscanf(buf, "MemTotal: %llu kB", &kb) == 1) { cached = kb * 1024; break; }
    }
    fclose(f);
    return cached;
}

static __u64 get_process_rss_bytes(__u32 pid)
{
    char path[256];
    FILE *f;
    __u64 size, resident, shared, text, lib, data, dt;
    snprintf(path, sizeof(path), "/proc/%u/statm", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    if (fscanf(f, "%llu %llu %llu %llu %llu %llu %llu",
              &size, &resident, &shared, &text, &lib, &data, &dt) != 7) {
        fclose(f); return 0;
    }
    fclose(f);
    return resident * 4096;
}

void sample_agent_cpu_usage(struct agent_state *state, unsigned long long now_ns)
{
    unsigned long long ticks, delta_ticks, delta_ns;
    long clk_tck;

    ticks = read_process_cpu_ticks(state->main_pid);
    if (ticks == 0) return;

    if (state->prev_cpu_sample_ns == 0 || state->prev_cpu_ticks == 0) {
        state->prev_cpu_ticks = ticks;
        state->prev_cpu_sample_ns = now_ns;
        return;
    }

    if (now_ns <= state->prev_cpu_sample_ns) {
        state->prev_cpu_ticks = ticks;
        state->prev_cpu_sample_ns = now_ns;
        return;
    }

    delta_ticks = ticks - state->prev_cpu_ticks;
    delta_ns = now_ns - state->prev_cpu_sample_ns;

    clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) clk_tck = 100;

    {
        unsigned long long max_ticks = (unsigned long long)((double)clk_tck * ((double)delta_ns / 1e9));
        if (delta_ticks > max_ticks) delta_ticks = max_ticks;
    }

    {
        long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (num_cpus <= 0) num_cpus = 1;
        state->metrics.cpu_usage = (double)delta_ticks / (double)clk_tck / ((double)delta_ns / 1e9) / (double)num_cpus;
    }

    state->prev_cpu_ticks = ticks;
    state->prev_cpu_sample_ns = now_ns;
}

void sample_agent_memory_usage(struct agent_state *state)
{
    __u64 rss = get_process_rss_bytes(state->main_pid);
    __u64 total = read_total_memory_bytes();
    if (total == 0) return;
    state->metrics.memory_usage = (double)rss / (double)total;
}

void publish_metrics_if_needed(struct agent_state *state, unsigned long long ts_ns)
{
    char key[128];
    if (!redis_ctx || !state || !state->in_use) return;

    if (state->metrics.window_start_ns == 0) {
        state->metrics.window_start_ns = ts_ns;
        state->metrics.last_active_ns = ts_ns;
        sample_agent_cpu_usage(state, ts_ns);
        return;
    }
    if (ts_ns - state->metrics.window_start_ns < METRIC_WINDOW_NS) {
        state->metrics.last_active_ns = ts_ns;
        return;
    }

    sample_agent_cpu_usage(state, ts_ns);
    sample_agent_memory_usage(state);

    snprintf(key, sizeof(key), "inter:metric:%s", state->agent_id);
    redisReply *reply = redisCommand(redis_ctx,
        "HSET %s cpu_usage %f memory_usage %f proc_exec_count %u proc_fork_count %u "
        "fs_open_count %u fs_read_count %u fs_write_count %u fs_unlink_count %u "
        "fs_chmod_count %u net_connect_count %u net_send_count %u net_recv_count %u "
        "api_call_count %u msg_sent_count %u msg_recv_count %u "
        "unique_files_count %u shell_exec_count %u sensitive_file_count %u workspace_violation %u "
        "ssl_msg_count %u ssl_total_bytes %llu "
        "window_start_ns %llu last_active_ns %llu",
        key,
        state->metrics.cpu_usage, state->metrics.memory_usage,
        state->metrics.proc_exec_count, state->metrics.proc_fork_count,
        state->metrics.fs_open_count, state->metrics.fs_read_count,
        state->metrics.fs_write_count, state->metrics.fs_unlink_count,
        state->metrics.fs_chmod_count, state->metrics.net_connect_count,
        state->metrics.net_send_count, state->metrics.net_recv_count,
        state->metrics.api_call_count, state->metrics.msg_sent_count,
        state->metrics.msg_recv_count,
        state->metrics.unique_files_count, state->metrics.shell_exec_count,
        state->metrics.sensitive_file_count, state->metrics.workspace_violation,
        state->metrics.ssl_msg_count, state->metrics.ssl_total_bytes,
        state->metrics.window_start_ns, state->metrics.last_active_ns);
    finish_redis_command("redisCommand", reply);

    memset(&state->metrics, 0, sizeof(state->metrics));
    state->metrics.window_start_ns = ts_ns;
    state->metrics.last_active_ns = ts_ns;
}

void update_metrics_for_sys_event(struct agent_state *state, const struct sys_event *event)
{
    const char *path = event->filename;
    if (!state) return;

    switch (event->event_type) {
    case EVENT_EXECVE:
        state->metrics.proc_exec_count++;
        if (strstr(path, "/sh") || strstr(path, "/bash") || strstr(path, "/zsh"))
            state->metrics.shell_exec_count++;
        break;
    case EVENT_FORK:
        state->metrics.proc_fork_count++;
        break;
    case EVENT_OPEN:
        state->metrics.fs_open_count++;
        remember_unique_file(&state->metrics, path);
        if (path_is_sensitive(path)) state->metrics.sensitive_file_count++;
        break;
    case EVENT_UNLINK:
        state->metrics.fs_unlink_count++;
        remember_unique_file(&state->metrics, path);
        if (path_is_sensitive(path)) state->metrics.sensitive_file_count++;
        if (path_is_workspace_violation(path)) state->metrics.workspace_violation++;
        break;
    case EVENT_CHMOD:
        state->metrics.fs_chmod_count++;
        remember_unique_file(&state->metrics, path);
        if (path_is_sensitive(path)) state->metrics.sensitive_file_count++;
        if (path_is_workspace_violation(path)) state->metrics.workspace_violation++;
        break;
    case EVENT_CONNECT:
    case EVENT_AGENT_COMM:
        state->metrics.net_connect_count++;
        state->metrics.api_call_count++;
        break;
    default:
        break;
    }
}

void update_metrics_for_ssl_event(struct agent_state *state, unsigned int event_type,
                                  const char *data, unsigned int data_len)
{
    if (!state) return;
    if (event_type == EVENT_SSL_READ) {
        state->metrics.net_recv_count++;
        state->metrics.msg_recv_count++;
    } else if (event_type == EVENT_SSL_WRITE) {
        state->metrics.net_send_count++;
        state->metrics.msg_sent_count++;
    }
    if (data && data_len > 0) {
        state->metrics.api_call_count++;
        state->metrics.ssl_msg_count++;
        state->metrics.ssl_total_bytes += data_len;
    }
}

int ship_resource_sample(__u32 level, __u64 target_id, __u64 cpu_ns, __u64 rss_bytes, int num_procs, __u64 cgroup_id)
{
    char value[1024];
    struct timespec ts;
    __u64 current_timestamp_ms, total_rss_kb, total_cpu_ms, cpu_usec;

    if (!redis_ctx) return -1;

    clock_gettime(CLOCK_REALTIME, &ts);
    current_timestamp_ms = (__u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    total_rss_kb = rss_bytes / 1024;
    total_cpu_ms = cpu_ns / 1000000;
    cpu_usec = cpu_ns / 1000;

    snprintf(value, sizeof(value),
        "{\"event\":\"RESOURCE_SAMPLE\",\"timestamp\":%llu,\"level\":%u,\"target_pid\":%llu,"
        "\"total_rss_kb\":%llu,\"total_cpu_user_ms\":%llu,\"total_cpu_sys_ms\":0,\"num_processes\":%d,"
        "\"cgroup_memory_bytes\":%llu,\"cgroup_memory_peak_bytes\":%llu,\"cgroup_cpu_usage_usec\":%llu}",
        current_timestamp_ms, level, target_id,
        total_rss_kb, total_cpu_ms, num_procs,
        rss_bytes, rss_bytes, cpu_usec);

    redisReply *reply = redisCommand(redis_ctx, "PUBLISH %s %s", "ebpf_resource_events", value);
    finish_redis_command("redisCommand", reply);
    return 0;
}

void fetch_and_ship_resources(int res_fd)
{
    struct res_key key = {0}, next_key;
    struct res_val val;
    struct agent_agg aggs[128];
    int agg_count = 0;
    __u64 sys_cpu_ns = 0, sys_rss_bytes = 0;
    int sys_procs = 0;

    if (!redis_ctx || res_fd < 0) return;
    memset(aggs, 0, sizeof(aggs));

    while (bpf_map_get_next_key(res_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(res_fd, &next_key, &val) == 0) {
            __u32 current_pid = (__u32)next_key.id;
            __u64 real_rss = get_process_rss_bytes(current_pid);
            int found = -1;

            ship_resource_sample(RES_LEVEL_PID, next_key.id, val.cpu_time_ns, real_rss, 1, val.cgroup_id);

            for (int i = 0; i < agg_count; i++) {
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
    if (sys_procs > 0)
        ship_resource_sample(RES_LEVEL_SYS, 0, sys_cpu_ns, sys_rss_bytes, sys_procs, 0);
}
