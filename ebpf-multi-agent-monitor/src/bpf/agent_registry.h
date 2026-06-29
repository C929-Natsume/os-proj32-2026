#ifndef AGENT_REGISTRY_H
#define AGENT_REGISTRY_H

#include <linux/types.h>

int register_agent(int map_fd, int pid, __u32 agent_id, const char *agent_name);

#endif
