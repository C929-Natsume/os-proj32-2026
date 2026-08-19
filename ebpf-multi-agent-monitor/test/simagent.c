#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>

int main(int argc, char **argv) {
    char tmpfile[64];
    int fd;

    /* 1. 绕过进程名识别 */
    prctl(PR_SET_NAME, "simagent", 0, 0, 0);
    printf("[SIMAGENT] PID=%d\n", getpid());
    usleep(200000);

    /* 2. 第1次 LLM 通信写文件 (触发 open+write → sys_event + raw_data) */
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/simagent_%d.json", getpid());

    const char *msg1 = "{\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],"
                       "\"model\":\"test\"}";
    fd = open(tmpfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, msg1, strlen(msg1));
        close(fd);
    }
    printf("[SIMAGENT] Step1: wrote LLM msg + file open\n");
    usleep(500000);

    /* 3. 第2次 LLM 通信 (再开新文件，触发 sys_event++ + raw_data=2 → 升格检查) */
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/simagent_%d_resp.json", getpid());
    const char *msg2 = "{\"tool_calls\":[{\"function\":{\"name\":\"read_file\"}}],"
                       "\"role\":\"assistant\"}";
    fd = open(tmpfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, msg2, strlen(msg2));
        close(fd);
    }
    printf("[SIMAGENT] Step2: wrote LLM msg + file open (triggers check_and_promote)\n");
    usleep(500000);

    /* 4. 等待升格 */
    printf("[SIMAGENT] Waiting for behavioral discovery...\n");
    sleep(5);

    printf("[SIMAGENT] Done.\n");
    return 0;
}
