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

    // 3. 匹配 "python" 和 "python3"
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' &&
        comm[3] == 'h' && comm[4] == 'o' && comm[5] == 'n') {
        return true;
    }

    return false;
}

static __always_inline bool try_auto_register(void *pid_map) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!is_claude_by_comm())
        return false;

    struct process_context new_ctx = {0};
    new_ctx.agent_id = AGENT_ID_AUTO_DETECT(pid);
    new_ctx.is_sub_agent = 1;
    new_ctx.parent_pid = 0;
    new_ctx.depth = 0;
    char default_name[] = "Auto-Agent";
    __builtin_memcpy(new_ctx.agent_name, default_name, sizeof(default_name));

    bpf_map_update_elem(pid_map, &pid, &new_ctx, BPF_ANY);
    return true;
}

// 过滤进程
static __always_inline bool is_claude_target() {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct process_context *ctx = bpf_map_lookup_elem(&claude_pid_map, &pid);
    if (ctx) return true;
    return try_auto_register(&claude_pid_map);
}

#endif /* __FILTER_H__ */