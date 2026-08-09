#ifndef AGENT_TRACKER_H
#define AGENT_TRACKER_H

#include "event_serializer.h"

#define MAX_TRACKED_AGENTS 128
#define MAX_AGENT_ID_LEN 64
#define MAX_WORKSPACE_LEN 256

struct agent_state {
    int in_use;
    unsigned int pid;
    unsigned int main_pid;
    char agent_id[MAX_AGENT_ID_LEN];
    char parent_agent_id[MAX_AGENT_ID_LEN];
    char comm[16];
    char workspace[MAX_WORKSPACE_LEN];
    struct agent_metrics metrics;
    unsigned long long prev_cpu_ticks;
    unsigned long long prev_cpu_sample_ns;
    int depth;
    int is_sub_agent;
};

struct probe_SSL_data_t;

struct agent_state *find_agent_by_pid(unsigned int pid);
struct agent_state *allocate_agent_slot(void);
struct agent_state *get_or_create_agent(unsigned int pid, unsigned int ppid,
                                        const char *comm, unsigned long long ts_ns,
                                        __u32 parent_agent_id, const char *parent_agent_name);
struct agent_state *get_or_create_ssl_fallback_agent(const struct probe_SSL_data_t *event);
int cmdline_contains_agent_marker(unsigned int pid, char *comm_out, size_t comm_out_len);
void publish_agent_registration(struct agent_state *state);
struct agent_state *create_behavioral_agent(unsigned int pid, const char *comm);

void agent_tracker_init(void);

#endif
