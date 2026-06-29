#include <string.h>
#include <bpf/bpf.h>
#include "common.h"
#include "agent_registry.h"

int register_agent(int map_fd, int pid, __u32 agent_id, const char *agent_name) {
    if (map_fd < 0) return -1;

    struct process_context ctx = {0};
    ctx.agent_id = agent_id;
    ctx.is_sub_agent = 1;
    ctx.parent_pid = 0;
    ctx.depth = 0;

    strncpy(ctx.agent_name, agent_name, MAX_AGENT_NAME_LEN - 1);
    ctx.agent_name[MAX_AGENT_NAME_LEN - 1] = '\0';

    return bpf_map_update_elem(map_fd, &pid, &ctx, BPF_ANY);
}
