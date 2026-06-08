#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sys_behavior.skel.h"
#include "common.h"

#define SYS_RB_PIN_PATH "/sys/fs/bpf/sys_rb"

static struct sys_behavior_bpf *sys_skel = NULL;

int setup_sys_behavior(void) {
    int err;

    printf("[SYS_BEHAVIOR] 正在加载内核监控探针...\n");
    sys_skel = sys_behavior_bpf__open_and_load();
    if (!sys_skel) {
        fprintf(stderr, "[SYS_BEHAVIOR] Failed to open and load BPF skeleton\n");
        return -1;
    }

    err = sys_behavior_bpf__attach(sys_skel);
    if (err) {
        fprintf(stderr, "[SYS_BEHAVIOR] Failed to attach BPF skeleton\n");
        sys_behavior_bpf__destroy(sys_skel);
        sys_skel = NULL;
        return -1;
    }

    // 钉固 (Pin) RingBuffer，以便独立的用户态程序 (ringbuf_handler) 可以跨进程读取
    bpf_map__unpin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
    err = bpf_map__pin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
    if (err) {
        fprintf(stderr, "[SYS_BEHAVIOR] Failed to pin ring buffer map to %s\n", SYS_RB_PIN_PATH);
        sys_behavior_bpf__destroy(sys_skel);
        sys_skel = NULL;
        return -1;
    }

    printf("[SYS_BEHAVIOR] 系统调用监控挂载成功，Ringbuf 钉固于: %s\n", SYS_RB_PIN_PATH);
    return 0;
}

// 注册智能体身份到内核 Map
/**
 * 将 loader.c 分配的智能体编号和名称注入到 sys_behavior.bpf.c 的 monitored_pids 表
 * * @param pid 目标智能体的物理进程 PID
 * @param agent_id 分配给该智能体的唯一数字编号
 * @param agent_name 分配给该智能体的文本名称
 */
int register_agent_sys(int pid, __u32 agent_id, const char *agent_name) {
    if (!sys_skel) {
        fprintf(stderr, "[-] register_agent_sys: Skeleton not loaded!\n");
        return -1;
    }
    
    struct process_context ctx = {0};
    ctx.agent_id = agent_id;
    ctx.is_sub_agent = 1; // 标记为智能体本身
    ctx.parent_pid = 0;   // 根节点没有父进程
    ctx.depth = 0;
    
    strncpy(ctx.agent_name, agent_name, MAX_AGENT_NAME_LEN - 1);
    ctx.agent_name[MAX_AGENT_NAME_LEN - 1] = '\0'; 

    int map_fd = bpf_map__fd(sys_skel->maps.monitored_pids);
    
    return bpf_map_update_elem(map_fd, &pid, &ctx, BPF_ANY);
}

void teardown_sys_behavior(void) {
    if (sys_skel) {
        bpf_map__unpin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
        sys_behavior_bpf__destroy(sys_skel);
        sys_skel = NULL;
        printf("[SYS_BEHAVIOR] 已卸载清理系统调用监控探针。\n");
    }
}