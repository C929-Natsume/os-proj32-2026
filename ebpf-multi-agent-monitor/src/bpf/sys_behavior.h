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
