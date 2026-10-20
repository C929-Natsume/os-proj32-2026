#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef __BPF__
#include "vmlinux.h"
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#else
#include <linux/types.h>
#include <sys/socket.h>
#endif

#define TASK_COMM_LEN 16
#define MAX_FILENAME 256
#define MAX_PATH 512

#define LOG_FILE "monitor.log"

#ifdef __BPF__
#undef LOG_FILE
#define LOG_FILE ""
#else
extern FILE *log_file;
extern int enable_log;
void log_print(const char *format, ...);
void print_tree_log(const char *format, ...);
#endif

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
    NET_SENDTO,
    NET_RECVFROM,
    NET_SSL_WRITE,
    NET_SSL_READ,
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

#define MAX_DATA_LEN 1024

/* ---------- IPv4/IPv6 地址联合结构 ---------- */
struct ip_addr {
    __u8 family;  // AF_INET / AF_INET6
    union {
        __u32 v4;
        __u8 v6[16];
    } addr;
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
            struct ip_addr saddr;
            __u16 sport;
            __u16 family;
        } connect;
        struct
        {
            int fd;
            struct ip_addr saddr;
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
            struct ip_addr saddr;
            __u16 sport;
            __u16 family;
        } accept;
        struct
        {
            int fd;
            struct ip_addr daddr;
            __u16 dport;
            __u64 bytes;
            char data[MAX_DATA_LEN];
            __u32 data_len;
        } send;
        struct
        {
            int fd;
            struct ip_addr saddr;
            __u16 sport;
            __u64 bytes;
            char data[MAX_DATA_LEN];
            __u32 data_len;
        } recv;
        struct
        {
            int fd;
        } close;
        struct
        {
            struct ip_addr saddr;
            __u16 sport;
            struct ip_addr daddr;
            __u16 dport;
            int oldstate;
            int newstate;
        } tcp_state;
        struct
        {
            int fd;
            struct ip_addr daddr;
            __u16 dport;
            __u64 bytes;
            char data[MAX_DATA_LEN];
            __u32 data_len;
        } sendto;
        struct
        {
            int fd;
            struct ip_addr saddr;
            __u16 sport;
            __u64 bytes;
            char data[MAX_DATA_LEN];
            __u32 data_len;
        } recvfrom;
        struct
        {
            int fd;
            __u64 bytes;
            char data[MAX_DATA_LEN];
            __u32 data_len;
        } ssl_write;
        struct
        {
            int fd;
            __u64 bytes;
            char data[MAX_DATA_LEN];
            __u32 data_len;
        } ssl_read;
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