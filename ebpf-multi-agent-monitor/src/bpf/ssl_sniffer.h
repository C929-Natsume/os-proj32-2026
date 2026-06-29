#ifndef __SSL_SNIFFER_H
#define __SSL_SNIFFER_H

#define MAX_BUF_SIZE 65536 // 单次截获最大 64KB 
#define RING_BUFFER_SIZE (4 * 1024 * 1024) // 4MB 环形缓冲区

// 区分来源引擎，便于用户态解析
enum sniff_engine {
    ENGINE_OPENSSL = 1,
    ENGINE_BORINGSSL = 2,
    ENGINE_GO_TLS = 3
};

struct probe_SSL_data_t {
    __u64 timestamp_ns;
    __u64 delta_ns;        // 函数执行耗时 (用于分析大模型响应延迟)
    __u32 pid;
    __u32 tid;
    __u32 uid;

    // 新增：智能体身份标识
    __u32 agent_id;
    char agent_name[MAX_AGENT_NAME_LEN];

    __u32 len;             // 数据实际长度
    __u32 buf_size;        // 拷贝到 eBPF 的安全截断长度
    int buf_filled;        // 标志位：是否成功拷贝数据
    int rw;                // 0: READ, 1: WRITE, 2: HANDSHAKE
    int is_handshake;      // 标志位：是否为握手包
    enum sniff_engine engine; 
    char comm[MAX_COMM_LEN];
    __u8 buf[MAX_BUF_SIZE];
};

#endif /* __SSLSNIFF_H */