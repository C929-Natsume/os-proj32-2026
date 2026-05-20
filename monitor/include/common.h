#ifndef __COMMON_H__
#define __COMMON_H__

// #include <linux/types.h>
#ifdef __BPF__
// BPF 程序：使用 vmlinux.h 代替所有内核类型头文件
#include "vmlinux.h"
#else
// 用户态程序：正常包含系统头文件
#include <linux/types.h>
// 其他用户态需要的头文件...
#endif

#define TASK_COMM_LEN 16
#define MAX_FILENAME 256
#define MAX_PATH 512

/* ---------- 事件分类 ---------- */
enum event_category
{
    CATEGORY_PROC = 1,
    CATEGORY_FS,
    CATEGORY_NET,
};

/* ---------- 进程事件子类型 ---------- */
enum proc_event_type
{
    PROC_EXEC,
    PROC_FORK,
    PROC_EXIT,
    PROC_SIGNAL,
    PROC_SETUID,
};

/* ---------- 文件事件子类型 ---------- */
enum fs_event_type
{
    FS_OPEN,
    FS_CLOSE,
    FS_READ,
    FS_WRITE,
    FS_UNLINK,
    FS_RENAME,
    FS_CHMOD,
    FS_CREATE,
    FS_RMDIR,
};

/* ---------- 网络事件子类型 ---------- */
enum net_event_type
{
    NET_SOCKET,
    NET_CONNECT,
    NET_BIND,
    NET_LISTEN,
    NET_ACCEPT,
    NET_SEND,
    NET_RECV,
    NET_CLOSE,
    NET_TCP_STATE,
};

/* ---------- 公共事件头 ---------- */
struct event_header
{
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 category; // event_category
    __u32 type;     // 子类型
    char comm[TASK_COMM_LEN];
};

/* ---------- 进程事件 ---------- */
struct proc_event
{
    struct event_header hdr;
    union
    {
        struct
        {
            char filename[MAX_FILENAME];
            __u32 parent_pid;
        } exec;
        struct
        {
            __u32 child_pid;
            __u32 parent_pid;
        } fork;
        struct
        {
            int exit_code;
        } exit;
        struct
        {
            int sig;
            __u32 target_pid;
        } signal;
        struct
        {
            __u32 uid;
            __u32 old_uid;
        } setuid;
    };
};

/* ---------- 文件事件 ---------- */
struct fs_event
{
    struct event_header hdr;
    union
    {
        struct
        {
            char filename[MAX_FILENAME];
            int flags;
        } open;
        struct
        {
            int fd;
        } close;
        struct
        {
            int fd;
            __u64 bytes;
            char filename[MAX_FILENAME];
        } read;
        struct
        {
            int fd;
            __u64 bytes;
            char filename[MAX_FILENAME];
        } write;
        struct
        {
            char filename[MAX_FILENAME];
        } unlink;
        struct
        {
            char oldname[MAX_FILENAME];
            char newname[MAX_FILENAME];
        } rename;
        struct
        {
            char filename[MAX_FILENAME];
            __u32 mode;
        } chmod;
        struct
        {
            char filename[MAX_FILENAME];
            int flags;
            __u32 mode;
        } create;
        struct
        {
            char dirname[MAX_FILENAME];
        } rmdir;
    };
};

/* ---------- 网络事件 ---------- */
struct net_event
{
    struct event_header hdr;
    union
    {
        struct
        {
            __u32 domain;
            __u32 type;
            __u32 protocol;
            int fd;
        } socket;
        struct
        {
            int fd;
            __u32 saddr;
            __u16 sport;
            __u16 family;
        } connect;
        struct
        {
            int fd;
            __u32 saddr;
            __u16 sport;
            __u16 family;
        } bind;
        struct
        {
            int fd;
            int backlog;
        } listen;
        struct
        {
            int fd;
            int newfd;
            __u32 saddr;
            __u16 sport;
            __u16 family;
        } accept;
        struct
        {
            int fd;
            __u32 daddr;
            __u16 dport;
            __u64 bytes;
        } send;
        struct
        {
            int fd;
            __u32 saddr;
            __u16 sport;
            __u64 bytes;
        } recv;
        struct
        {
            int fd;
        } close;
        struct
        {
            __u32 saddr;
            __u16 sport;
            __u32 daddr;
            __u16 dport;
            int oldstate;
            int newstate;
        } tcp_state;
    };
};

/* ---------- 共享的进程信息（用于 pid_tree map） ---------- */
struct proc_info
{
    __u32 parent_pid;
    char comm[TASK_COMM_LEN];
    __u64 start_time; // 可扩展
};

/* ---------- 用于 fd -> path 映射的 key ---------- */
struct fd_key
{
    __u32 pid;
    __u32 fd;
};

/* ---------- 用于 fd -> socket 属性的结构 ---------- */
struct sock_info
{
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u16 family;
    __u8 protocol; // IPPROTO_TCP / UDP
    __u8 state;    // TCP state
};

#endif /* __COMMON_H__ */