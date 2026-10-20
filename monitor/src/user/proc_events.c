#include <stdio.h>
#include <arpa/inet.h>
#include "proc.skel.h"
#include "proc_tree.h"
#include "common.h"

int handle_proc_event(void *ctx, void *data, size_t data_sz)
{
    struct proc_event *e = data;

    switch (e->hdr.type)
    {
    case PROC_EXEC:
        update_exec(e->hdr.pid, e->exec.filename, e->hdr.comm);
        update_file_exec(e->hdr.pid, e->exec.filename);
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

    if (!is_claude_related(e->hdr.pid))
        return 0;

    switch (e->hdr.type)
    {
    case PROC_EXEC:
        log_print("[%llu] PID %d (%s) [EXEC] %s, parent=%u\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->exec.filename, e->exec.parent_pid);
        break;
    case PROC_FORK:
        log_print("[%llu] PID %d (%s) [FORK] %u -> %u\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->fork.parent_pid, e->fork.child_pid);
        break;
    case PROC_EXIT:
        log_print("[%llu] PID %d (%s) [EXIT] code=%d\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->exit.exit_code);
        break;
    case PROC_SIGNAL:
        log_print("[%llu] PID %d (%s) [SIGNAL] sig=%d target=%u\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->signal.sig, e->signal.target_pid);
        break;
    case PROC_SETUID:
        log_print("[%llu] PID %d (%s) [SETUID] uid=%u old=%u\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->setuid.uid, e->setuid.old_uid);
        break;
    default:
        log_print("[%llu] PID %d (%s) UNKNOWN proc type %d\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->hdr.type);
    }
    return 0;
}