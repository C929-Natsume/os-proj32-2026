#include "vmlinux.h"
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "common.h"

#define MAX_ENTRIES 10240

// -----------------------------------------------------------
// Maps 定义
// -----------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} start_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, void*);
} bufs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, struct process_context); 
} agent_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ssl_drop_counter SEC(".maps");

static __always_inline void inc_ssl_drop(void) {
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&ssl_drop_counter, &key);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

// SSL_read_ex / SSL_write_ex 的 size_t* 输出参数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, size_t*);
} readbytes_ptrs SEC(".maps");

// -----------------------------------------------------------
// 工业级进程/用户隔离过滤器
// -----------------------------------------------------------
const volatile pid_t targ_pid = 0;
const volatile uid_t targ_uid = -1;

static __always_inline bool trace_allowed(u32 uid, u32 pid) {
    if (targ_pid && targ_pid != pid) return false;
    if (targ_uid != -1 && targ_uid != uid) return false;
    return true;
}

// -----------------------------------------------------------
// 统一数据组装与提交通道
// -----------------------------------------------------------
static __always_inline int process_data_exit(void *buf, int len, int rw, bool is_handshake, enum sniff_engine engine) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts  = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) return 0;
    if (len <= 0 && !is_handshake) return 0;

    u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    u64 delta_ns = tsp ? (ts - *tsp) : 0;

    u32 u32_len = (u32)len;

    struct process_context *pctx = bpf_map_lookup_elem(&agent_info_map, &pid);
    u32   aid = pctx ? pctx->agent_id : 0;
    char  aname[MAX_AGENT_NAME_LEN] = {0};
    if (pctx)
        __builtin_memcpy(aname, pctx->agent_name, MAX_AGENT_NAME_LEN);

    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bool skip = false;
    if (comm[0] == 'g' && comm[1] == 'i' && comm[2] == 't' && comm[3] == '\0')
        skip = true;
    else if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h')
        skip = true;

    /* ── chunk metadata ── */
    u16 total = (u32_len + MAX_BUF_SIZE - 1) / MAX_BUF_SIZE;
    if (total > 32) total = 32;  /* cap at 2MB */

    /* ── submit chunks in bounded loop ── */
    #pragma unroll
    for (u16 i = 0; i < 32; i++) {
        if (i >= total) break;

        u32 off = i * (u32)MAX_BUF_SIZE;
        u32 sz  = u32_len - off;
        if (sz > MAX_BUF_SIZE) sz = MAX_BUF_SIZE;

        struct probe_SSL_data_t *c = bpf_ringbuf_reserve(&rb, sizeof(*c), 0);
        if (!c) break;  /* ring buffer full, stop here */

        c->agent_id   = aid;
        __builtin_memcpy(c->agent_name, aname, sizeof(c->agent_name));
        c->timestamp_ns = ts;
        c->delta_ns     = (i == 0) ? delta_ns : 0;
        c->pid          = pid;
        c->tid          = tid;
        c->uid          = uid;
        c->len          = u32_len;
        c->rw           = rw;
        c->is_handshake = (int)is_handshake;
        c->engine       = engine;
        c->chunk_index  = i;
        c->chunk_total  = total;
        __builtin_memcpy(c->comm, comm, sizeof(c->comm));

        if (buf && len > 0 && !skip) {
            int ret = bpf_probe_read_user(&c->buf, sz, (const char *)buf + off);
            c->buf_filled = (ret == 0) ? 1 : 0;
            c->buf_size   = (ret == 0) ? sz : 0;
        } else {
            c->buf_filled = 0;
            c->buf_size   = 0;
        }
        bpf_ringbuf_submit(c, 0);
    }

    return 0;
}

// ===========================================================
// 模块 1: 标准 OpenSSL / BoringSSL (Python / Node.js)
// ===========================================================
SEC("uprobe/SSL_rw_enter")
int BPF_UPROBE(probe_SSL_rw_enter, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    
    if (!trace_allowed(bpf_get_current_uid_gid(), pid_tgid >> 32)) return 0;

    bpf_map_update_elem(&bufs, &tid, &buf, BPF_ANY);
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    int len = PT_REGS_RC(ctx);
    void **bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (bufp) process_data_exit(*bufp, len, 0, false, ENGINE_OPENSSL);
    
    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    int len = PT_REGS_RC(ctx);
    void **bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (bufp) process_data_exit(*bufp, len, 1, false, ENGINE_OPENSSL);
    
    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);
    return 0;
}

// ===========================================================
// 模块 2: OpenSSL_ex 扩展函数 (处理现代大模型 SDK)
// ===========================================================
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(probe_SSL_write_ex_enter, void *ssl, void *buf, size_t num, size_t *written) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(bpf_get_current_uid_gid(), pid_tgid >> 32)) return 0;

    bpf_map_update_elem(&readbytes_ptrs, &tid, &written, BPF_ANY);
    bpf_map_update_elem(&bufs, &tid, &buf, BPF_ANY);
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    // tail-call 修复: entry 直接提交, 不依赖 uretprobe
    process_data_exit(buf, (int)num, 1, false, ENGINE_OPENSSL);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int BPF_URETPROBE(probe_SSL_write_ex_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    size_t **readbytes_ptr = bpf_map_lookup_elem(&readbytes_ptrs, &tid);
    if (!readbytes_ptr) return 0;

    size_t written = 0;
    bpf_probe_read_user(&written, sizeof(written), *readbytes_ptr);
    bpf_map_delete_elem(&readbytes_ptrs, &tid);

    int ret = PT_REGS_RC(ctx);
    int len = (ret == 1) ? written : 0;

    void **bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (bufp) process_data_exit(*bufp, len, 1, false, ENGINE_OPENSSL);

    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);
    return 0;
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(probe_SSL_read_ex_enter, void *ssl, void *buf, size_t num, size_t *readbytes) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    if (!trace_allowed(bpf_get_current_uid_gid(), pid_tgid >> 32)) return 0;
    bpf_map_update_elem(&readbytes_ptrs, &tid, &readbytes, BPF_ANY);
    bpf_map_update_elem(&bufs, &tid, &buf, BPF_ANY);
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(probe_SSL_read_ex_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    size_t **readbytes_ptr = bpf_map_lookup_elem(&readbytes_ptrs, &tid);
    if (!readbytes_ptr) return 0;
    size_t read_len = 0;
    bpf_probe_read_user(&read_len, sizeof(read_len), *readbytes_ptr);
    bpf_map_delete_elem(&readbytes_ptrs, &tid);
    
    int ret = PT_REGS_RC(ctx);
    int len = (ret == 1) ? read_len : 0;
    void **bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (bufp) process_data_exit(*bufp, len, 0, false, ENGINE_OPENSSL);
    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);
    return 0;
}

// ===========================================================
// 模块 3: Go 语言 Agent 支持
// ===========================================================
// Go ABIInternal 规范因架构而异：
//   x86_64:  BX = Data指针, CX = 长度, AX = 返回值
//   arm64:   X0 = Data指针, X1 = 长度, X0 = 返回值
#if defined(__TARGET_ARCH_x86)
    #define GO_BUF_REG    regs->bx
    #define GO_LEN_REG    regs->cx
    #define GO_RET_REG    regs->ax
#elif defined(__TARGET_ARCH_arm64)
    #define GO_BUF_REG    regs->x0
    #define GO_LEN_REG    regs->x1
    #define GO_RET_REG    regs->x0
#else
    #define GO_BUF_REG    regs->bx
    #define GO_LEN_REG    regs->cx
    #define GO_RET_REG    regs->ax
#endif

// Write: Go 同步 write，数据已组装好，无需等待 exit
SEC("uprobe/go_tls_write")
int BPF_UPROBE(go_tls_write_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!trace_allowed(bpf_get_current_uid_gid(), pid_tgid >> 32)) return 0;

    struct pt_regs *regs = (struct pt_regs *)ctx;
    void *buf = (void *)GO_BUF_REG;
    int len = (int)GO_LEN_REG;

    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)pid_tgid;
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    process_data_exit(buf, len, 1, false, ENGINE_GO_TLS);
    return 0;
}

// Read enter: 存储 buf 指针供 exit 使用
// 注意：Go 使用 M:N 协程调度（goroutine），协程在不同线程间迁移时
// tid 会改变，导致 enter/exit 配对丢失。这种情况无法通过 tid-keyed map 完美解决。
// 内核 5.15+ 的 bpf_get_attach_cookie() 和 BPF cookie 可缓解此问题。
SEC("uprobe/go_tls_read")
int BPF_UPROBE(go_tls_read_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!trace_allowed(bpf_get_current_uid_gid(), pid_tgid >> 32)) return 0;

    struct pt_regs *regs = (struct pt_regs *)ctx;
    void *buf = (void *)GO_BUF_REG;
    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)pid_tgid;

    bpf_map_update_elem(&bufs, &tid, &buf, BPF_ANY);
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

// Read exit: 读取返回值并组装事件
// 若 Go 协程在 read 操作期间切换了线程，tid 不匹配导致丢失数据
// 可以升级为 bpf_get_attach_cookie() 做 1:1 标记（需要内核 5.15+）
SEC("uretprobe/go_tls_read")
int BPF_URETPROBE(go_tls_read_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();

    void **bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (!bufp) {
        // 协程切换：enter 和 exit 不在同一线程，清理可能残留的下一组 tid 记录
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    struct pt_regs *regs = (struct pt_regs *)ctx;
    int len = (int)GO_RET_REG;
    if (len > 0) {
        process_data_exit(*bufp, len, 0, false, ENGINE_GO_TLS);
    }

    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);
    return 0;
}

// ===========================================================
// 模块 4: 握手性能分析
// ===========================================================
SEC("uprobe/do_handshake")
int BPF_UPROBE(probe_SSL_do_handshake_enter, void *ssl) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    if (!trace_allowed(bpf_get_current_uid_gid(), pid_tgid >> 32)) return 0;
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe/do_handshake")
int BPF_URETPROBE(probe_SSL_do_handshake_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx);
    
    if (ret > 0) process_data_exit(NULL, ret, 2, true, ENGINE_OPENSSL); // rw=2 表示握手
    bpf_map_delete_elem(&start_ns, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";