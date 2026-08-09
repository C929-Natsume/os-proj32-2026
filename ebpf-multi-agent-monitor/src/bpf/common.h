#ifndef COMMON_H
#define COMMON_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 512

#define MAX_AGENTS 128
#define MAX_AGENT_NAME_LEN 32

#define AGENT_ID_KERNEL_SNIFFED  0x80000000  // 内核嗅探标志位
#define AGENT_ID_AUTO_DETECT(pid) (AGENT_ID_KERNEL_SNIFFED | (pid))
#define AGENT_ID_IS_KERNEL_SNIFFED(id)  (((id) & 0x80000000) != 0)
#define AGENT_ID_EXTRACT_PID(id)        ((id) & 0x7FFFFFFF)

#define AGENT_DISCOVERY_BEHAVIORAL 0x40000000  // 行为识别标志位
#define AGENT_ID_BEHAVIORAL(pid) (AGENT_DISCOVERY_BEHAVIORAL | (pid))
#define AGENT_ID_IS_BEHAVIORAL(id) (((id) & 0x40000000) != 0)

#define DISCOVERY_SYS_EVENT_THRESHOLD   1
#define DISCOVERY_LLM_MATCH_THRESHOLD   2
#define DISCOVERY_TIME_WINDOW_NS        (30ULL * 1000000000ULL)

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
    EVENT_CHMOD,
    EVENT_AGENT_COMM,        // 智能体间通信事件
    EVENT_STDIO_READ = 10,   // MCP stdio 读取 (stdin)
    EVENT_STDIO_WRITE,       // MCP stdio 写入 (stdout/stderr)
    EVENT_TCP_SEND,          // 纯文本 TCP 发送 (localhost HTTP/A2A/ACP/ANP)
    EVENT_TCP_RECV,          // 纯文本 TCP 接收
    EVENT_AGENT_DISCOVERY,   // 行为识别发现新智能体
};

// 监听端口-智能体映射
struct tcp_listen_key {
    __u32 saddr;   // IPv4 地址
    __u16 sport;   // 端口
    __u16 pad;
};

// 捕获 MCP stdio、A2A/ACP/ANP localhost HTTP 通信
#define RAW_DATA_BUF_SIZE  16384  // 单次截获最大 16KB

enum raw_data_source {
    RAW_SRC_STDIO = 1,   // stdin/stdout 捕获
    RAW_SRC_TCP   = 2,   // 纯文本 TCP 捕获
};

struct raw_data_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 agent_id;
    char agent_name[MAX_AGENT_NAME_LEN];
    __u32 parent_agent_id;
    char parent_agent_name[MAX_AGENT_NAME_LEN];
    __u32 data_len;              // 原始数据长度
    __u32 buf_size;              // 实际拷贝到 eBPF 的长度
    int buf_filled;              // 是否成功拷贝数据
    int direction;               // 0=READ/RECV, 1=WRITE/SEND
    enum raw_data_source source; // 数据来源
    __u32 fd;                    // 文件描述符
    __u32 peer_pid;              // stdio: 对端 PID (父/子进程)
    char comm[MAX_COMM_LEN];
    __u8 buf[RAW_DATA_BUF_SIZE];
};

// 新增：进程上下文结构体，用于在 eBPF Map 中记录进程的血缘和智能体归属
struct process_context {
    __u32 agent_id;                           // 智能体编号
    char agent_name[MAX_AGENT_NAME_LEN];      // 智能体名称
    __u32 parent_pid;                         // 父进程 PID
    __u32 parent_agent_id;                    // 调用方智能体编号（父智能体身份）
    char parent_agent_name[MAX_AGENT_NAME_LEN]; // 调用方智能体名称
    __u8 is_sub_agent;                        // 身份标识：2=候选子智能体, 1=已确认子智能体, 0=普通系统工具
    __u8 depth;                               // 调用树深度
};

// fd-对端身份映射
struct fd_peer_info {
    __u32 peer_pid;
    __u32 peer_agent_id;
    char peer_agent_name[MAX_AGENT_NAME_LEN];
};

// 未知进程候选评分结构体 (行为识别引擎)
struct candidate_score {
    __u64 sys_event_count;       // 高危系统调用次数
    __u64 raw_data_count;        // LLM数据匹配次数
    __u64 first_seen_ns;         // 首次发现时间戳
    __u8  flags;                 // bit0=有高危sys, bit1=有LLM数据, bit7=已注册
};

#include "sys_behavior.h"
#include "ssl_sniffer.h"

#endif