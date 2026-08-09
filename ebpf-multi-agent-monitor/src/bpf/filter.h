#ifndef __FILTER_H__
#define __FILTER_H__

#include "vmlinux.h"
#include <bpf_helpers.h>

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
    if (comm[0] == 'b' && comm[1] == 'u' && comm[2] == 'n') return true;

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

#define LLM_FP_SCAN_LEN 32

static __always_inline bool has_llm_protocol_fingerprint(const __u8 *buf, __u32 len) {
    if (!buf || len < 16)
        return false;

    #pragma unroll
    for (int i = 0; i < LLM_FP_SCAN_LEN - 6; i++) {
        if ((__u32)(i + 11) <= len &&
            buf[i+0] == '"' && buf[i+1] == 'r' && buf[i+2] == 'o' &&
            buf[i+3] == 'l' && buf[i+4] == 'e' && buf[i+5] == '"')
            return true;
    }

    #pragma unroll
    for (int i = 0; i < LLM_FP_SCAN_LEN - 7; i++) {
        if ((__u32)(i + 12) <= len &&
            buf[i+0] == '"' && buf[i+1] == 't' && buf[i+2] == 'o' &&
            buf[i+3] == 'o' && buf[i+4] == 'l' && buf[i+5] == '_' &&
            buf[i+6] == 'c' && buf[i+7] == 'a' && buf[i+8] == 'l' &&
            buf[i+9] == 'l' && buf[i+10] == 's' && buf[i+11] == '"')
            return true;
    }

    #pragma unroll
    for (int i = 0; i < LLM_FP_SCAN_LEN - 7; i++) {
        if ((__u32)(i + 10) <= len &&
            buf[i+0] == '"' && buf[i+1] == 'm' && buf[i+2] == 'e' &&
            buf[i+3] == 's' && buf[i+4] == 's' && buf[i+5] == 'a' &&
            buf[i+6] == 'g' && buf[i+7] == 'e' && buf[i+8] == 's' &&
            buf[i+9] == '"')
            return true;
    }

    return false;
}

#endif /* __FILTER_H__ */