#ifndef COMMON_H
#define COMMON_H

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 512

#define MAX_AGENTS 128
#define MAX_AGENT_NAME_LEN 32

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_FORK,
    EVENT_OPEN,
    EVENT_UNLINK,
    EVENT_CONNECT,
    EVENT_SSL_READ,
    EVENT_SSL_WRITE,
    EVENT_CHMOD
};

// 新增：进程上下文结构体，用于在 eBPF Map 中记录进程的血缘和智能体归属
struct process_context {
    __u32 agent_id;                           // 智能体编号
    char agent_name[MAX_AGENT_NAME_LEN];      // 智能体名称
    __u32 parent_pid;                         // 父进程 PID
    __u8 is_sub_agent;                        // 身份标识：1=母/子智能体，0=普通系统工具
    __u8 depth;                               // 调用树深度
};

#include "sys_behavior.h"
#include "ssl_sniffer.h"

#endif