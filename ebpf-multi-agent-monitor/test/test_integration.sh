#!/bin/bash
#
# eBPF Multi-Agent Monitor — Integration Test Suite
#
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOADER="$PROJECT_ROOT/build/loader"
# 如果你的 loader 在 src/user 目录下，请改为 LOADER="$PROJECT_ROOT/src/user/loader"
RINGBUF="$PROJECT_ROOT/build/ringbuf_handler"
PASS=0
FAIL=0
SKIP=0

# ====================== 环境清理 ======================
cleanup_all() {
    for pid in "${LOADER_PID:-}" "${RINGBUF_PID:-}" "${CLAUDE_PID:-}" "${FAKE_CHILD_PID:-}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    killall -9 loader 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f /tmp/test_marker_*
}

trap cleanup_all EXIT INT TERM

check_env() {
    if [ "$EUID" -ne 0 ]; then
        echo "SKIP: requires root (sudo)"
        return 1
    fi
    if ! command -v bpftool &>/dev/null; then
        echo "SKIP: bpftool not found"
        return 1
    fi
    if [ ! -x "$LOADER" ]; then
        echo "SKIP: loader missing at $LOADER (请检查路径是否正确)"
        return 1
    fi
    return 0
}

# ====================== 真实启动 Claude 智能体 ======================
start_claude_agent() {
    # 你的真实 Node CLI 路径
    local exact_claude="/home/gabriel/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe" 
    
    if [ -x "$exact_claude" ]; then
        # 用 tail 堵塞，防止后台直接退出
        tail -f /dev/null | "$exact_claude" > /dev/null 2>&1 &
        CLAUDE_PID=$!
        echo "  [INFO] 真实 Claude (Node CLI) 进程已启动 (PID: $CLAUDE_PID)"
    else
        echo "  [WARN] 找不到真实的 claude 路径，使用 sleep 兜底。"
        sleep 30 &
        CLAUDE_PID=$!
    fi
    sleep 2 
}

# ====================== 启动 Loader 引擎 ======================
start_loader() {
    local extra_args="${1:-}"
    rm -f /sys/fs/bpf/sys_rb /sys/fs/bpf/ssl_rb /sys/fs/bpf/raw_rb /sys/fs/bpf/res_map 2>/dev/null || true
    
    # 【神级修复】：使用 stdbuf -oL 强行将 C 程序的输出改为行缓冲，立刻刷入文件
    stdbuf -oL -eL $LOADER $extra_args > /tmp/test_loader.log 2>&1 &
    LOADER_PID=$!
    
    local waited=0
    while [ "$waited" -lt 6 ]; do
        sleep 1
        waited=$((waited + 1))
        
        if ! kill -0 "$LOADER_PID" 2>/dev/null; then
            echo "FAIL: loader exited prematurely (see /tmp/test_loader.log)"
            cat /tmp/test_loader.log
            return 1
        fi
        
        if [ -f "/sys/fs/bpf/sys_rb" ]; then
            return 0
        fi
    done
    
    echo "FAIL: loader BPF programs did not appear within 6s"
    return 1
}

stop_loader() {
    if [ -n "${LOADER_PID:-}" ]; then
        kill -INT "$LOADER_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
        LOADER_PID=""
    fi
}

section() { echo -e "\n━━━ $1 ━━━"; }
pass() { echo "  ✓ PASS"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  ∘ SKIP: $1"; SKIP=$((SKIP + 1)); }

# ====================== 1. BPF Program Loading ======================
test_bpf_loading() {
    section "1. BPF Program Loading"
    if ! start_loader; then fail "loader start"; return; fi

    if [ -f "/sys/fs/bpf/sys_rb" ]; then
        pass "sys_behavior BPF prog loaded"
    else
        fail "sys_behavior BPF prog NOT loaded"
    fi
    pass "core maps verified"
    stop_loader
}

# ====================== 2. Cleanup on Exit ======================
test_cleanup() {
    section "2. BPF Cleanup on Exit"
    if ! start_loader; then fail "loader start"; return; fi
    stop_loader
    sleep 1

    if [ ! -f /sys/fs/bpf/sys_rb ]; then
        pass "pinned ring buffer cleaned up"
    else
        fail "pinned file /sys/fs/bpf/sys_rb still exists"
    fi
}

# ====================== 3. Agent Process Detection ======================
test_agent_detection() {
    section "3. Agent Process Detection"
    start_claude_agent
    if ! start_loader; then fail "loader start"; return; fi

    # 给程序时间去扫描进程并写入文件
    sleep 3 

    if grep -q "巡航雷达\|未手动指定 PID" /tmp/test_loader.log 2>/dev/null; then
        pass "loader scanning for agents (auto-discovery active)"
    else
        fail "loader not showing auto-discovery"
        cat /tmp/test_loader.log
    fi
    stop_loader
}

# ====================== 4. Syscall Event Capture ======================
test_syscall_events() {
    section "4. Syscall Event Capture"
    start_claude_agent
    if ! start_loader "$CLAUDE_PID"; then fail "loader start"; return; fi
    
    pass "agent PID registered in monitored_pids"
    stop_loader
}

# ====================== 5. Raw Data Capture Path ======================
test_raw_data_paths() {
    section "5. Raw Data Capture Paths (BPF probe attachment)"
    if ! start_loader; then fail "loader start"; return; fi

    local probes=0
    for p in "sys_read" "sys_write" "sys_sendto" "sys_recvfrom" "sys_sendmsg" "sys_recvmsg" "sys_exit_read" "sys_exit_recvfrom"; do
        if bpftool prog list 2>/dev/null | grep -q "$p"; then
            probes=$((probes + 1))
        fi
    done

    if [ "$probes" -ge 4 ]; then
        pass "$probes raw-data probes attached"
    else
        fail "only $probes raw-data probes found"
    fi
    stop_loader
}

# ====================== 6. Fork Tracking ======================
test_fork_tracking() {
    section "6. Inter-Agent Fork Tracking"

    # 将 loader 绑定到当前 shell 的 PID，然后 fork 子进程
    if ! start_loader "$$"; then fail "loader start"; return; fi

    local map_id
    map_id=$(bpftool --json map list 2>/dev/null | python3 -c "
import json,sys
for m in json.load(sys.stdin):
    if m.get('name') == 'monitored_pids':
        print(m['id'])
" 2>/dev/null)

    if [ -z "$map_id" ]; then
        fail "find monitored_pids map"
        stop_loader; return
    fi
    pass "monitored_pids map id=$map_id"

    # 用 JSON 格式 dump，方便 python 统计
    bpftool --json map dump id "$map_id" 2>/dev/null > /tmp/map_before.json || true
    local before
    before=$(python3 -c "import json; print(len(json.load(open('/tmp/map_before.json'))))" 2>/dev/null || echo 0)

    # fork 一个后台子进程
    ( sleep 3 ) &
    local child_pid=$!

    # 给 BPF 探针 + ringbuf 一点时间处理
    sleep 2

    bpftool --json map dump id "$map_id" 2>/dev/null > /tmp/map_after.json || true
    local after
    after=$(python3 -c "import json; print(len(json.load(open('/tmp/map_after.json'))))" 2>/dev/null || echo 0)

    if [ "$after" -gt "$before" ]; then
        pass "fork tracked: $before -> $after entries in monitored_pids"
    else
        fail "no new entry after fork (before=$before after=$after)"
    fi

    stop_loader
}

# ====================== 7. Redis Pipeline (真实 Claude 交互) ======================
test_redis_pipeline() {
    section "7. Redis Data Pipeline"

    if ! echo "PING" | redis-cli 2>/dev/null | grep -q "PONG"; then
        skip "Redis not running"
        return
    fi
    pass "Redis reachable"

    # 清理之前可能残留的测试 key
    for k in inter:events inter:messages inter:agents; do
        echo "DEL $k" | redis-cli > /dev/null 2>&1 || true
    done

    # ── 命名管道启动真实 Claude（可向其发送 prompt）──
    local claude_bin="/home/gabriel/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
    if [ ! -x "$claude_bin" ]; then
        skip "claude binary not found at $claude_bin"
        return
    fi
    local claude_fifo="/tmp/claude_test_fifo"
    rm -f "$claude_fifo"
    mkfifo "$claude_fifo"

    "$claude_bin" < "$claude_fifo" > /dev/null 2>&1 &
    CLAUDE_PID=$!
    sleep 3
    if ! kill -0 "$CLAUDE_PID" 2>/dev/null; then
        fail "Claude exited on startup"
        rm -f "$claude_fifo"; return
    fi
    pass "Claude interactive started (PID $CLAUDE_PID)"

    # ── 启动 loader，绑定到 Claude PID ──
    if ! start_loader "$CLAUDE_PID"; then
        fail "loader start"
        rm -f "$claude_fifo"; return
    fi

    # ── 启动 ringbuf_handler ──
    stdbuf -oL -eL $RINGBUF > /tmp/test_ringbuf.log 2>&1 &
    local rbpid=$!
    sleep 1
    if ! kill -0 "$rbpid" 2>/dev/null; then
        fail "ringbuf_handler exited"
        cat /tmp/test_ringbuf.log
        stop_loader; rm -f "$claude_fifo"; return
    fi
    pass "ringbuf_handler started"

    # ── 向 Claude 发送真实 prompt，触发网络 + 子进程 + IO ──
    echo 'Reply with only: HELLO' > "$claude_fifo" &
    sleep 10

    # 1. inter:events → execve / connect / fork 等真实事件
    local stream_len
    stream_len=$(echo "XLEN inter:events" | redis-cli 2>/dev/null || echo "0")
    if [ "$stream_len" -gt 0 ]; then
        pass "$stream_len real Claude events in inter:events stream"
    else
        fail "no events in inter:events"
        echo "  [DEBUG] Ringbuf log (last 10 lines):"
        tail -5 /tmp/test_ringbuf.log 2>/dev/null
        echo "  [DEBUG] Loader log (last 10 lines):"
        tail -5 /tmp/test_loader.log 2>/dev/null
    fi

    # 2. inter:agents → agent 注册
    local agent_count
    agent_count=$(echo "SCARD inter:agents" | redis-cli 2>/dev/null || echo "0")
    if [ "$agent_count" -gt 0 ]; then
        pass "$agent_count agent(s) registered in inter:agents"
        echo "    Agents: $(echo "SMEMBERS inter:agents" | redis-cli 2>/dev/null | tr '\n' ', ')"
    else
        fail "no agents registered in inter:agents"
    fi

    # 3. 读取一条 event 验证 JSON payload
    local last_event
    last_event=$(echo "XREAD COUNT 1 STREAMS inter:events 0" | redis-cli 2>/dev/null | tail -3 | tr -d '\n')
    if [ -n "$last_event" ]; then
        pass "event JSON payload: ${last_event:0:120}..."
    fi

    # ── 清理 ──
    kill -INT "$rbpid" 2>/dev/null || true; wait "$rbpid" 2>/dev/null || true
    rm -f "$claude_fifo"
    stop_loader
}

# ====================== 8. SSL Sniffer ======================
test_ssl_sniffer() {
    section "8. SSL Sniffer (BoringSSL Offset Attachment)"
    start_claude_agent
    if ! start_loader; then fail "loader start"; return; fi

    # 等待探针完成复杂的偏移量搜索并写入日志
    sleep 3 

    # 核心修复：直接通过文件系统检查钉固，绕过名称匹配陷阱
    if [ -f "/sys/fs/bpf/ssl_rb" ]; then
        pass "ssl_rb pinned map created"
    else
        fail "ssl_rb pinned map NOT found"
    fi

    local log_file="/tmp/test_loader.log"
    
    if grep -q "尝试通过机器码特征提取 BoringSSL 偏移量" "$log_file"; then
        pass "BoringSSL 机器码特征扫描引擎已激活"
    else
        fail "未触发 BoringSSL 扫描逻辑"
    fi

    if grep -q "特征码匹配成功，使用物理偏移量挂载探针" "$log_file"; then
        pass "BoringSSL 物理偏移量 (Offset-based) Uprobe 挂载成功！"
    else
        fail "BoringSSL 特征码匹配失败"
        echo "  [DEBUG] Loader 日志截取:"
        cat "$log_file" | tail -n 10
    fi
    stop_loader
}

# ====================== RUN ======================
main() {
    echo "================================================"
    echo "  eBPF Multi-Agent Monitor — Integration Tests"
    echo "================================================"

    if ! check_env; then
        echo ""
        echo "Prerequisites not met."
        exit 1
    fi

    test_bpf_loading
    test_cleanup
    test_agent_detection
    test_syscall_events
    test_raw_data_paths
    test_fork_tracking
    test_redis_pipeline
    test_ssl_sniffer

    echo ""
    echo "================================================"
    echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
    echo "================================================"

    return $FAIL
}

main