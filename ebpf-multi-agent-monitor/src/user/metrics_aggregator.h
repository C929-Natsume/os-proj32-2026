#ifndef METRICS_AGGREGATOR_H
#define METRICS_AGGREGATOR_H

#include "../bpf/common.h"
#include "agent_tracker.h"

#define METRIC_WINDOW_NS (30ULL * 1000ULL * 1000ULL * 1000ULL)

void sample_agent_cpu_usage(struct agent_state *state, unsigned long long now_ns);
void sample_agent_memory_usage(struct agent_state *state);
void publish_metrics_if_needed(struct agent_state *state, unsigned long long ts_ns);
void update_metrics_for_sys_event(struct agent_state *state, const struct sys_event *event);
void update_metrics_for_ssl_event(struct agent_state *state, unsigned int event_type,
                                  const char *data, unsigned int data_len);
int ship_resource_sample(__u32 level, __u64 target_id, __u64 cpu_ns, __u64 rss_bytes, int num_procs, __u64 cgroup_id);
void fetch_and_ship_resources(int res_fd);

#endif
