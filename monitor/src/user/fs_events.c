#include <stdio.h>
#include <stdlib.h>
#include "fs.skel.h"
#include "proc_tree.h"
#include "intra_analyzer.h"

static int demo_all_enabled(void)
{
    const char *v = getenv("MONITOR_DEMO_ALL");
    return v && (v[0] == '1' || v[0] == 'y' || v[0] == 'Y');
}

int handle_fs_event(void *ctx, void *data, size_t data_sz)
{
    struct fs_event *e = data;

    // claude
    if (!demo_all_enabled() && !is_claude_related(e->hdr.pid))
        return 0;

    intra_on_fs_event(e);

    // printf("[%llu] PID %d (%s) ", e->hdr.timestamp_ns, e->hdr.pid, e->hdr.comm);
    switch (e->hdr.type)
    {
    case FS_OPEN:
        printf("OPEN  %s flags=0x%x\n", e->open.filename, e->open.flags);
        break;
    case FS_CLOSE:
        printf("CLOSE fd=%d\n", e->close.fd);
        break;
    case FS_READ:
        if (e->read.filename[0])
            printf("READ  fd=%d bytes=%llu file=%s\n", e->read.fd, e->read.bytes, e->read.filename);
        else
            printf("READ  fd=%d bytes=%llu\n", e->read.fd, e->read.bytes);
        break;
    case FS_WRITE:
        if (e->write.filename[0])
            printf("WRITE fd=%d bytes=%llu file=%s\n", e->write.fd, e->write.bytes, e->write.filename);
        else
            printf("WRITE fd=%d bytes=%llu\n", e->write.fd, e->write.bytes);
        break;
    case FS_UNLINK:
        printf("UNLINK %s\n", e->unlink.filename);
        break;
    case FS_RENAME:
        printf("RENAME %s -> %s\n", e->rename.oldname, e->rename.newname);
        break;
    case FS_CHMOD:
        printf("CHMOD %s mode=%o\n", e->chmod.filename, e->chmod.mode);
        break;
    case FS_CREATE:
        printf("CREATE %s flags=0x%x mode=%o\n", e->create.filename, e->create.flags, e->create.mode);
        break;
    case FS_RMDIR:
        printf("RMDIR %s\n", e->rmdir.dirname);
        break;
    default:
        printf("UNKNOWN fs type %d\n", e->hdr.type);
    }
    return 0;
}
