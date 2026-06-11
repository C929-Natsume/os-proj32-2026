#ifndef COMMON_H
#define COMMON_H

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 512

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_FORK,
    EVENT_OPEN,
    EVENT_UNLINK,
    EVENT_CONNECT,
    EVENT_SSL_READ,
    EVENT_SSL_WRITE,
};

struct sys_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
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

struct ssl_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u64 timestamp;
    char comm[MAX_COMM_LEN];
    __u32 data_len;
    char data[4096];
};

#endif
