#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sys_behavior.skel.h"
#include "sys_behavior.h"

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

void teardown_sys_behavior(void) {
    if (sys_skel) {
        bpf_map__unpin(sys_skel->maps.rb, SYS_RB_PIN_PATH);
        sys_behavior_bpf__destroy(sys_skel);
        sys_skel = NULL;
        printf("[SYS_BEHAVIOR] 已卸载清理系统调用监控探针。\n");
    }
}