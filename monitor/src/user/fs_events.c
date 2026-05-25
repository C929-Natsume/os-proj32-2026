#include <stdio.h>
#include "fs.skel.h"
#include "proc_tree.h"
#include "common.h"

int handle_fs_event(void *ctx, void *data, size_t data_sz)
{
    struct fs_event *e = data;

    if (!is_claude_related(e->hdr.pid))
        return 0;

    switch (e->hdr.type)
    {
    case FS_CREATE:
        update_file_create(e->hdr.pid, e->create.filename);
        break;
    case FS_UNLINK:
        update_file_delete(e->hdr.pid, e->unlink.filename);
        break;
    case FS_RMDIR:
        update_file_delete(e->hdr.pid, e->rmdir.dirname);
        break;
    case FS_READ:
        update_file_read(e->hdr.pid, e->read.filename, e->read.bytes);
        break;
    case FS_WRITE:
        update_file_write(e->hdr.pid, e->write.filename, e->write.bytes);
        break;
    case FS_CHMOD:
        update_file_chmod(e->hdr.pid, e->chmod.filename, e->chmod.mode);
        break;
    default:
        break;
    }

    switch (e->hdr.type)
    {
    case FS_OPEN:
        log_print("[%llu] PID %d (%s) OPEN %s flags=0x%x\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->open.filename, e->open.flags);
        break;
    case FS_CLOSE:
        log_print("[%llu] PID %d (%s) CLOSE fd=%d\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->close.fd);
        break;
    case FS_READ:
        log_print("[%llu] PID %d (%s) READ fd=%d bytes=%llu\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->read.fd, e->read.bytes);
        break;
    case FS_WRITE:
        log_print("[%llu] PID %d (%s) WRITE fd=%d bytes=%llu\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->write.fd, e->write.bytes);
        break;
    case FS_UNLINK:
        log_print("[%llu] PID %d (%s) UNLINK %s\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->unlink.filename);
        break;
    case FS_RENAME:
        log_print("[%llu] PID %d (%s) RENAME %s -> %s\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->rename.oldname, e->rename.newname);
        break;
    case FS_CHMOD:
        log_print("[%llu] PID %d (%s) CHMOD %s mode=%o\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->chmod.filename, e->chmod.mode);
        break;
    case FS_CREATE:
        log_print("[%llu] PID %d (%s) CREATE %s flags=0x%x mode=%o\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->create.filename, e->create.flags, e->create.mode);
        break;
    case FS_RMDIR:
        log_print("[%llu] PID %d (%s) RMDIR %s\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->rmdir.dirname);
        break;
    default:
        log_print("[%llu] PID %d (%s) UNKNOWN fs type %d\n", 
                  e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm, 
                  e->hdr.type);
    }
    return 0;
}