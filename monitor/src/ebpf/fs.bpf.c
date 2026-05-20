#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define O_CREAT 0x00000040

struct open_how_user
{
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

/* ---------- 共享 pid_tree（复用已 pin 的 map） ---------- */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct proc_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_tree SEC(".maps");

/* ---------- 内部 fd->path 映射 ---------- */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct fd_key);
    __type(value, char[MAX_FILENAME]);
} fd_path_map SEC(".maps");

/* ---------- 临时保存 open 路径参数（按线程） ---------- */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); // pid_tgid
    __type(value, char[MAX_FILENAME]);
} open_path_map SEC(".maps");

/* ---------- 文件事件 ring buffer ---------- */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} fs_events SEC(".maps");

static __always_inline void bpf_memset(void *s, int c, __u32 n)
{
    for (__u32 i = 0; i < n; i++)
        ((char *)s)[i] = (char)c;
}

static __always_inline void fill_header(struct event_header *hdr, int cat, int type)
{
    hdr->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    hdr->pid = pid_tgid >> 32;
    hdr->tid = (__u32)pid_tgid;
    hdr->category = cat;
    hdr->type = type;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

/* ---------- OPENAT ---------- */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    char *filename = (char *)ctx->args[1];
    int flags = (int)ctx->args[2];
    __u32 mode = (__u32)ctx->args[3];
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    char path[MAX_FILENAME] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), filename) > 0)
        bpf_map_update_elem(&open_path_map, &pid_tgid, path, BPF_ANY);

    if (flags & O_CREAT)
    {
        struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
        if (!e)
            return 0;
        bpf_memset(e, 0, sizeof(*e));
        fill_header(&e->hdr, CATEGORY_FS, FS_CREATE);
        bpf_probe_read_user_str(e->create.filename, MAX_FILENAME, filename);
        e->create.flags = flags;
        e->create.mode = mode;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_OPEN);
    bpf_probe_read_user_str(e->open.filename, MAX_FILENAME, filename);
    e->open.flags = flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- OPENAT2 ---------- */
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
    char *filename = (char *)ctx->args[1];
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct open_how_user how = {};
    int flags = 0;
    __u32 mode = 0;

    bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]);
    flags = (int)how.flags;
    mode = (__u32)how.mode;

    char path[MAX_FILENAME] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), filename) > 0)
        bpf_map_update_elem(&open_path_map, &pid_tgid, path, BPF_ANY);

    if (flags & O_CREAT)
    {
        struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
        if (!e)
            return 0;
        bpf_memset(e, 0, sizeof(*e));
        fill_header(&e->hdr, CATEGORY_FS, FS_CREATE);
        bpf_probe_read_user_str(e->create.filename, MAX_FILENAME, filename);
        e->create.flags = flags;
        e->create.mode = mode;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_OPEN);
    bpf_probe_read_user_str(e->open.filename, MAX_FILENAME, filename);
    e->open.flags = flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- OPENAT exit 用于记录 fd ---------- */
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;
    if (ret < 0)
    {
        bpf_map_delete_elem(&open_path_map, &pid_tgid);
        return 0;
    }
    int fd = (int)ret;

    __u32 pid = pid_tgid >> 32;

    struct fd_key key = {.pid = pid, .fd = fd};
    char *path = bpf_map_lookup_elem(&open_path_map, &pid_tgid);
    if (path)
    {
        bpf_map_update_elem(&fd_path_map, &key, path, BPF_ANY);
    }
    else
    {
        char unknown[MAX_FILENAME] = "unknown";
        bpf_map_update_elem(&fd_path_map, &key, unknown, BPF_ANY);
    }

    bpf_map_delete_elem(&open_path_map, &pid_tgid);
    return 0;
}

/* ---------- OPENAT2 exit 用于记录 fd ---------- */
SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;
    if (ret < 0)
    {
        bpf_map_delete_elem(&open_path_map, &pid_tgid);
        return 0;
    }
    int fd = (int)ret;

    __u32 pid = pid_tgid >> 32;

    struct fd_key key = {.pid = pid, .fd = fd};
    char *path = bpf_map_lookup_elem(&open_path_map, &pid_tgid);
    if (path)
    {
        bpf_map_update_elem(&fd_path_map, &key, path, BPF_ANY);
    }
    else
    {
        char unknown[MAX_FILENAME] = "unknown";
        bpf_map_update_elem(&fd_path_map, &key, unknown, BPF_ANY);
    }

    bpf_map_delete_elem(&open_path_map, &pid_tgid);
    return 0;
}

/* ---------- CLOSE ---------- */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_CLOSE);
    int fd = (int)ctx->args[0];
    e->close.fd = fd;

    // 清理 fd_path_map
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_key key = {.pid = pid_tgid >> 32, .fd = fd};
    bpf_map_delete_elem(&fd_path_map, &key);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- 临时存储当前进程的 fd ---------- */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // pid_tgid
    __type(value, int); // fd
} pid_fd_map SEC(".maps");

/* ---------- READ enter ---------- */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pid_fd_map, &pid_tgid, &fd, BPF_ANY);
    return 0;
}

/* ---------- READ (exit) ---------- */
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    int *fd_ptr = bpf_map_lookup_elem(&pid_fd_map, &pid_tgid);
    if (!fd_ptr)
        return 0;

    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_READ);
    e->read.fd = *fd_ptr;
    e->read.bytes = (__u64)ret;
    struct fd_key key = {.pid = pid, .fd = *fd_ptr};
    char *path = bpf_map_lookup_elem(&fd_path_map, &key);
    if (path)
        __builtin_memcpy(e->read.filename, path, MAX_FILENAME);
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pid_fd_map, &pid_tgid);
    return 0;
}

/* ---------- WRITE enter ---------- */
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pid_fd_map, &pid_tgid, &fd, BPF_ANY);
    return 0;
}

/* ---------- WRITE (exit) ---------- */
SEC("tracepoint/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    int *fd_ptr = bpf_map_lookup_elem(&pid_fd_map, &pid_tgid);
    if (!fd_ptr)
        return 0;

    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_WRITE);
    e->write.fd = *fd_ptr;
    e->write.bytes = (__u64)ret;
    struct fd_key key = {.pid = pid, .fd = *fd_ptr};
    char *path = bpf_map_lookup_elem(&fd_path_map, &key);
    if (path)
        __builtin_memcpy(e->write.filename, path, MAX_FILENAME);
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pid_fd_map, &pid_tgid);
    return 0;
}

/* ---------- RENAME ---------- */
SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_RENAME);
    bpf_probe_read_user_str(e->rename.oldname, MAX_FILENAME, (char *)ctx->args[0]);
    bpf_probe_read_user_str(e->rename.newname, MAX_FILENAME, (char *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- CHMOD ---------- */
SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_CHMOD);
    bpf_probe_read_user_str(e->chmod.filename, MAX_FILENAME, (char *)ctx->args[0]);
    e->chmod.mode = (__u32)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- UNLINK ---------- */
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_UNLINK);
    bpf_probe_read_user_str(e->unlink.filename, MAX_FILENAME, (char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- RMDIR ---------- */
SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_rmdir(struct trace_event_raw_sys_enter *ctx)
{
    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return 0;
    bpf_memset(e, 0, sizeof(*e));
    fill_header(&e->hdr, CATEGORY_FS, FS_RMDIR);
    bpf_probe_read_user_str(e->rmdir.dirname, MAX_FILENAME, (char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
