#ifndef __FILTER_H__
#define __FILTER_H__

#include "vmlinux.h"
#include <bpf_helpers.h>

// ================= 过滤配置 =================
// 维护一个动态的 PID 白名单 Map。
// 用户态 loader 可以将明确的 claude PID 写入此 Map，
// 或者在内核态中匹配到进程名后自动加入白名单。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, struct process_context);
} claude_pid_map SEC(".maps");

// 辅助函数：通过进程名 (comm) 判断是否是目标
static __always_inline bool is_claude_by_comm() {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 1. 匹配 "claude"
    if (comm[0] == 'c' && comm[1] == 'l' && comm[2] == 'a' && 
        comm[3] == 'u' && comm[4] == 'd' && comm[5] == 'e') {
        return true;
    }
    
    // 2. 匹配 "node" 或 "bun"
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd') return true;
    if (comm[0] == 'B' && comm[1] == 'u' && comm[2] == 'n') return true;

    // 3. 【核心修复】：放行 "python" 和 "python3"，为了我们的终极标准测试！
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h') {
        return true;
    }

    return false;
}

// ================= 主过滤函数 =================
// 返回 true 表示是 Claude 进程，需要放行捕获；返回 false 表示忽略
static __always_inline bool is_claude_target() {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 1. 优先查 PID 白名单 Map（最高效）
    struct process_context *ctx = bpf_map_lookup_elem(&claude_pid_map, &pid);
    if (ctx) {
        return true;
    }

    // 2. 如果 Map 里没有，检查进程名是否匹配
    if (is_claude_by_comm()) {
        // 发现是 Claude/Node/Python 进程后，将其 PID 动态加入白名单
        struct process_context new_ctx = {0};
        
        // 赋予特殊的编号 9999，代表它是被内核态“嗅探”到的独立母体
        // 区别于 Loader 主动发现并分配的 1000, 1001
        new_ctx.agent_id = 9999;  
        new_ctx.is_sub_agent = 1;
        new_ctx.parent_pid = 0;
        new_ctx.depth = 0;
        
        // 填入默认名称
        char default_name[] = "Auto-Agent";
        __builtin_memcpy(new_ctx.agent_name, default_name, sizeof(default_name));

        // 写入 Map
        bpf_map_update_elem(&claude_pid_map, &pid, &new_ctx, BPF_ANY);
        
        return true;
    }

    return false;
}

#endif /* __FILTER_H__ */