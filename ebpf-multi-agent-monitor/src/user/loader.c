#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

extern int setup_sys_behavior(void);
extern void teardown_sys_behavior(void);

extern int setup_ssl_sniffer(int target_pid);
extern void teardown_ssl_sniffer(void);

static volatile int running = 1;

// 捕获 Ctrl+C
void sig_handler(int sig) {
    running = 0;
}

// ================= 寻找 Agent 进程的 PID =================
int auto_discover_target_pid(void) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // 检查 PID 目录
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

        // cmdline 参数是用 '\0' 分隔的，替换为空格方便 strstr 匹配
        for (size_t i = 0; i < bytes_read; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }

        // 匹配 Agent 脚本名（待优化）
        if ((strstr(cmdline, "claude") != NULL || 
             strstr(cmdline, "anthropic") != NULL || 
             strstr(cmdline, "agent_test.py") != NULL) &&
            strstr(cmdline, ".vscode") == NULL &&     // 排除 cmdline 中的 vscode 插件
            strstr(cmdline, ".vscode") == NULL &&  
            strstr(cmdline, "./loader") == NULL)
        {
            closedir(dir);
            return pid;
        }
    }
    closedir(dir);
    return -1;
}

int main(int argc, char **argv) {
    printf("=======================================================\n");
    printf("[LOADER] 自适应 eBPF 多智能体监控平台主控引擎启动...\n");
    printf("=======================================================\n");

    // 注册信号监听
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // ================= 1. 挂载系统调用行为引擎 =================
    // 系统行为是全局监控的，尽早启动可以防止漏掉早期的执行动作
    printf("[LOADER] [1/2] 正在拉起系统行为追踪引擎...\n");
    if (setup_sys_behavior() != 0) {
        fprintf(stderr, "[-] 系统行为引擎启动失败！\n");
        return 1;
    }

    // ================= 2. 确定目标 PID =================
    int target_pid = -1;
    
    if (argc >= 2) {
        // 手动指定模式
        target_pid = atoi(argv[1]);
        if (target_pid <= 0) {
            fprintf(stderr, "[!] 无效的 PID: %s\n", argv[1]);
            teardown_sys_behavior();
            return 1;
        }
        printf("[LOADER] 使用手动指定的目标 PID: %d\n", target_pid);
    } else {
        // 自动巡航模式
        printf("[LOADER] 未手动指定 PID... 启动自动巡航雷达\n");
        printf("[LOADER] 正在等待多智能体 (Agent) 进程启动 (按 Ctrl+C 退出)...\n");
        
        while (running && target_pid <= 0) {
            target_pid = auto_discover_target_pid();
            if (target_pid <= 0) {
                sleep(1); // 没找到就沉睡 1 秒，不消耗 CPU
            }
        }
        
        // 如果在等待期间按下了 Ctrl+C
        if (!running) {
            teardown_sys_behavior();
            return 0;
        }
        printf("\n[LOADER] 自动获取到智能体 PID: %d\n", target_pid);
    }

    // ================= 3. 挂载 SSL 加密流量嗅探引擎 =================
    printf("[LOADER] [2/2] 正在拉起 SSL 加密流量解密引擎 (Target PID: %d)...\n", target_pid);
    if (setup_ssl_sniffer(target_pid) != 0) {
        fprintf(stderr, "[-] SSL 嗅探引擎启动失败！\n");
        teardown_sys_behavior(); // 失败时回滚系统探针
        return 1;
    }

    printf("\n[LOADER] 双引擎探针部署完毕，管道已钉固！\n");
    printf("[LOADER] 系统监控中... (按 Ctrl+C 安全退出)\n");
    
    // 主线程沉睡，释放 CPU，纯靠内核态 eBPF 事件驱动
    while (running) { 
        sleep(1); 
    }

    // ================= 4. 优雅卸载与资源回收 =================
    printf("\n\n[LOADER] 收到终止信号，正在卸载内核探针并清理环境...\n");
    teardown_ssl_sniffer();
    teardown_sys_behavior();
    
    printf("[LOADER] 清理完成，安全退出。Bye!\n");
    return 0;
}