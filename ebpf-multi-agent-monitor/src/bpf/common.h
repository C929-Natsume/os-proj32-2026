#ifndef COMMON_H
#define COMMON_H

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 512

#define MAX_AGENTS 128
#define MAX_AGENT_NAME_LEN 32

#define AGENT_ID_KERNEL_SNIFFED  0x80000000  // 内核嗅探标志位
#define AGENT_ID_AUTO_DETECT(pid) (AGENT_ID_KERNEL_SNIFFED | (pid))
#define AGENT_ID_IS_KERNEL_SNIFFED(id)  (((id) & 0x80000000) != 0)
#define AGENT_ID_EXTRACT_PID(id)        ((id) & 0x7FFFFFFF)

// 增加监测： cpu 占用 & 内存占用结构
enum resource_level {
    RES_LEVEL_SYS    = 1,  // 系统全局级
    RES_LEVEL_CGROUP = 2,  // Cgroup 隔离级
    RES_LEVEL_AGENT  = 3,  // 进程树级
    RES_LEVEL_PID    = 4   // 独立进程级
};

struct res_key {
    __u32 level;
    __u64 id; 
};
struct res_val {
    __u64 cpu_time_ns;   // 累计 CPU 执行时间 (纳秒)
    __u64 mem_rss_bytes; // 物理内存驻留集大小 (字节)
    __u32 agent_id;      // 归属的智能体 ID
    __u64 cgroup_id;     // 归属的 Cgroup ID
};

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