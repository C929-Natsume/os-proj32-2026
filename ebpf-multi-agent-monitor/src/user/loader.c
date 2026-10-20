#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <linux/types.h>
#include "../bpf/common.h"

#define MAX_KNOWN_PIDS 2048

__u32 global_agent_id_counter = 1000; // 初始agent_id = 1000

extern int setup_sys_behavior(void);
extern void teardown_sys_behavior(void);

extern int setup_ssl_sniffer(int *target_pids, int count);
extern void teardown_ssl_sniffer(void);

// 向内核态 Map 注册身份信息
extern int register_agent_sys(int pid, __u32 agent_id, const char *agent_name);
extern int register_agent_ssl(int pid, __u32 agent_id, const char *agent_name);

extern int add_new_agents_ssl(int *target_pids, int count);

static volatile int running = 1;

// 用于同时存储 PID 和智能体类型的结构体：智能体/插件
struct agent_info {
    int pid;
    char prefix[16]; // 用于区分身份，例如 "Sys" 或 "VSCode"
};

// PID 去重记忆池
static int known_pids[MAX_KNOWN_PIDS];
static int known_pids_count = 0;

static bool is_known_pid(int pid) {
    for (int i = 0; i < known_pids_count; i++) {
        if (known_pids[i] == pid) return true;
    }
    return false;
}

static void add_known_pid(int pid) {
    if (known_pids_count < MAX_KNOWN_PIDS) {
        known_pids[known_pids_count++] = pid;
    }
}

// 捕获 Ctrl+C
void sig_handler(int sig) {
    running = 0;
}

// ================= 寻找 Agent 进程的 PID =================
int auto_discover_target_pids(struct agent_info *agents, int max_count) {
    DIR *dir = opendir("/proc");
    if (!dir) return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max_count) {
        if (!isdigit(entry->d_name[0])) continue;

        int pid = atoi(entry->d_name);
        char cmd_path[256];
        snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", pid);
        
        FILE *f = fopen(cmd_path, "r");
        if (!f) continue;
        
        char cmdline[2048] = {0};
        size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        
        if (bytes_read == 0) continue;

        for (size_t i = 0; i < bytes_read; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }

        // 排除 loader 探针自身
        if (strstr(cmdline, "./loader") != NULL) continue;

        // 匹配核心 AI 智能体特征词
        bool is_target = false;
        if (strstr(cmdline, "claude") != NULL || 
            strstr(cmdline, "anthropic") != NULL || 
            strstr(cmdline, "opencode") != NULL ||
            strstr(cmdline, "agent_test") != NULL) 
        {
            is_target = true;
        }

        // 如果命中了特征，判断其运行环境并打标签
        if (is_target) {
            agents[count].pid = pid;
            
            // 如果路径中包含 .vscode 或 vscode-server，判定为插件智能体
            if (strstr(cmdline, ".vscode") != NULL || strstr(cmdline, "vscode") != NULL) {
                strcpy(agents[count].prefix, "VSCode");
            } else {
                // 否则判定为系统级全局智能体
                strcpy(agents[count].prefix, "Sys");
            }
            count++;
        }
    }
    closedir(dir);
    return count;
}

int main(int argc, char **argv) {
    printf("=======================================================\n");
    printf("[LOADER] 自适应 eBPF 多智能体监控平台主控引擎启动...\n");
    printf("=======================================================\n");

    // 注册信号监听
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // ================= 1. 挂载系统调用行为引擎 =================
    printf("[LOADER] [1/3] 正在拉起系统行为追踪引擎...\n");
    if (setup_sys_behavior() != 0) {
        fprintf(stderr, "[-] 系统行为引擎启动失败！\n");
        return 1;
    }

    // ================= 2. 雷达扫描目标 PID =================
    struct agent_info discovered_agents[MAX_AGENTS]; 
    int target_pids[MAX_AGENTS];                     
    int agent_count = 0;
    
    if (argc >= 2) {
        target_pids[0] = atoi(argv[1]);
        if (target_pids[0] <= 0) {
            fprintf(stderr, "[!] 无效的 PID: %s\n", argv[1]);
            teardown_sys_behavior();
            return 1;
        }
        discovered_agents[0].pid = target_pids[0];
        strcpy(discovered_agents[0].prefix, "Manual"); // 手动指定的打上 Manual 标签
        agent_count = 1;
        printf("[LOADER] 使用手动指定的目标 PID: %d\n", target_pids[0]);
    } else {
        printf("[LOADER] 未手动指定 PID... 启动自动巡航雷达\n");
        printf("[LOADER] 正在等待多智能体 (Agent/VSCode插件) 启动 (按 Ctrl+C 退出)...\n");
        
        while (running && agent_count == 0) {
            agent_count = auto_discover_target_pids(discovered_agents, MAX_AGENTS);
            if (agent_count == 0) sleep(1); 
        }
        
        if (!running) { teardown_sys_behavior(); return 0; }
        
        printf("\n[LOADER] 自动获取到 %d 个智能体母体进程。\n", agent_count);
        
        // 将结构体中的 PID 提取出来，准备传给底层 C 语言挂载接口
        for(int i = 0; i < agent_count; i++) {
            target_pids[i] = discovered_agents[i].pid;
        }
    }
    // ================= 3. 挂载 SSL 加密流量嗅探引擎 =================
    printf("[LOADER] [2/3] 正在拉起并发 SSL 加密流量解密引擎...\n");
    if (setup_ssl_sniffer(target_pids, agent_count) != 0) {
        fprintf(stderr, "[-] SSL 嗅探引擎启动失败！\n");
        teardown_sys_behavior(); 
        return 1;
    }

    // ================= 4. 分配身份并注册到内核 Map =================
    printf("[LOADER] [3/3] 正在分配智能体全局身份并注入内核...\n");
    for (int i = 0; i < agent_count; i++) {
        __u32 pid = target_pids[i];
        __u32 assigned_id = global_agent_id_counter++;
        char assigned_name[MAX_AGENT_NAME_LEN];
        // 【核心修改】：利用识别到的前缀动态生成 Agent 名称
        // 结果示例: "VSCode-Agent-1001" 或 "Sys-Agent-1002"
        snprintf(assigned_name, MAX_AGENT_NAME_LEN, "%s-Agent-%u", discovered_agents[i].prefix, assigned_id);

        register_agent_sys(pid, assigned_id, assigned_name);
        register_agent_ssl(pid, assigned_id, assigned_name);
        add_known_pid(pid); 

        printf("  -> [初始绑定] 成功 | PID: %d <==> ID: %u, 名称: %s\n", pid, assigned_id, assigned_name);
    }

    printf("\n[LOADER] 双引擎探针部署完毕，管道已钉固！\n");
    printf("[LOADER] 系统监控中... (按 Ctrl+C 安全退出)\n");
    
    // 运行时添加新智能体
    while (running) { 
        sleep(2); // 每 2 秒扫描一次
        
        struct agent_info current_agents[MAX_AGENTS];
        int current_count = auto_discover_target_pids(current_agents, MAX_AGENTS);
        
        int new_pids[MAX_AGENTS];
        struct agent_info new_agents[MAX_AGENTS];
        int new_count = 0;

        // 过滤出不在记忆池中的 PID
        for (int i = 0; i < current_count; i++) {
            if (!is_known_pid(current_agents[i].pid)) {
                new_agents[new_count] = current_agents[i];
                new_pids[new_count] = current_agents[i].pid;
                new_count++;
            }
        }

        // 触发增量挂载流程
        if (new_count > 0) {
            printf("\n[LOADER]检测到 %d 个新智能体启动！触发增量挂载...\n", new_count);
            
            add_new_agents_ssl(new_pids, new_count);
            for (int i = 0; i < new_count; i++) {
                __u32 pid = new_agents[i].pid;
                __u32 assigned_id = global_agent_id_counter++;
                char assigned_name[MAX_AGENT_NAME_LEN];
                snprintf(assigned_name, MAX_AGENT_NAME_LEN, "%s-Agent-%u", new_agents[i].prefix, assigned_id);

                register_agent_sys(pid, assigned_id, assigned_name);
                register_agent_ssl(pid, assigned_id, assigned_name);
                add_known_pid(pid); 

                printf("  -> [动态新增] 绑定成功 | PID: %d <==> ID: %u, 名称: %s\n", pid, assigned_id, assigned_name);
            }
        }
    }

    // ================= 5. 卸载与资源回收 =================
    printf("\n\n[LOADER] 收到终止信号，正在卸载内核探针并清理环境...\n");
    teardown_ssl_sniffer();
    teardown_sys_behavior();
    
    printf("[LOADER] 清理完成，安全退出。Bye!\n");
    return 0;
}