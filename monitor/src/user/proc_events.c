#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "proc.skel.h"
#include "proc_tree.h"
#include "intra_analyzer.h"

static int demo_all_enabled(void)
{
    const char *v = getenv("MONITOR_DEMO_ALL");
    return v && (v[0] == '1' || v[0] == 'y' || v[0] == 'Y');
}

int handle_proc_event(void *ctx, void *data, size_t data_sz)
{
    struct proc_event *e = data;

    // 先更新进程信息（创建节点、更新关系）
    switch (e->hdr.type)
    {
    case PROC_EXEC:
        update_exec(e->hdr.pid, e->exec.filename);
        break;
    case PROC_FORK:
        add_child(e->fork.parent_pid, e->fork.child_pid);
        break;
    case PROC_EXIT:
        remove_node(e->hdr.pid);
        break;
    default:
        break;
    }

    // 然后判断是否与 claude 相关
    if (!demo_all_enabled() && !is_claude_related(e->hdr.pid))
        return 0;

    intra_on_proc_event(e);

    // 如果相关，则输出事件
    // printf("[%llu] PID %d (%s) ", e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm);
    switch (e->hdr.type)
    {
    case PROC_EXEC:
        printf("[EXEC]  %s, parent=%u\n", e->exec.filename, e->exec.parent_pid);
        break;
    case PROC_FORK:
        printf("[FORK]  %u -> %u\n", e->fork.parent_pid, e->fork.child_pid);
        break;
    case PROC_EXIT:
        printf("[EXIT]  code=%d\n", e->exit.exit_code);
        break;
    case PROC_SIGNAL:
        printf("[SIGNAL] sig=%d target=%u\n", e->signal.sig, e->signal.target_pid);
        break;
    case PROC_SETUID:
        printf("[SETUID] uid=%u old=%u\n", e->setuid.uid, e->setuid.old_uid);
        break;
    default:
        printf("UNKNOWN proc type %d\n", e->hdr.type);
    }
    return 0;
}
