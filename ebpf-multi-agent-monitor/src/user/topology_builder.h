#ifndef TOPOLOGY_BUILDER_H
#define TOPOLOGY_BUILDER_H

#include "../bpf/common.h"
#include "agent_tracker.h"

#define MAX_STREAM_DATA 512

void publish_agent_comm_edge(const char *src_agent_id, const char *dst_agent_id,
                             const char *dip, int dport, unsigned long long ts_ns);
void publish_message_event(struct agent_state *state, const char *protocol, const char *msg_type,
                           const char *data, unsigned int bytes, unsigned long long ts_ns,
                           unsigned int pid, unsigned int tid);
void publish_inter_event(struct agent_state *state, const struct sys_event *event);

#endif
