#ifndef __SYS_BEHAVIOR_H
#define __SYS_BEHAVIOR_H

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 512

struct sys_event {
    __u32 event_type;
    __u32 pid;
    __u32 child_pid;
    __u32 uid;
    __u64 timestamp;

    // 智能体身份标识
    __u32 agent_id;
    char agent_name[MAX_AGENT_NAME_LEN];

    // 调用方智能体
    __u32 parent_agent_id;
    char parent_agent_name[MAX_AGENT_NAME_LEN];

    // 对端智能体
    __u32 peer_agent_id;
    __u32 peer_pid;
    char peer_agent_name[MAX_AGENT_NAME_LEN];

    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
    union {
        struct {
            int exit_code;
        } execve;
        struct {
            int family;
            int dport;
            char dip[46];
        } connect;
        struct {
            __u32 mode;
        } open;
    };
};

#endif
