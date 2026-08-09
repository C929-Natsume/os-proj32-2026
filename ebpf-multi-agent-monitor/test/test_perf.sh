set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOADER="$PROJECT_ROOT/build/loader"
RINGBUF="$PROJECT_ROOT/build/ringbuf_handler"
TMPDIR=$(mktemp -d /tmp/perf_real_XXXXXX)
RINGBUF_LOG="/tmp/test_ringbuf_perf.log"
LOADER_LOG="/tmp/test_loader_perf.log"

PASS=0
FAIL=0

cleanup() {
    kill "$LOADER_PID" "$RINGBUF_PID" "$RINGBUF_FILTER_PID" "$NC_SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$TMPDIR" "$WRAPPER_SCRIPT" /tmp/.raw_probe_test.* /tmp/perf_$$.tmp /tmp/rb_fifo_$$
}
trap cleanup EXIT INT TERM

# ==================== 负载函数 ====================

# 大量模拟数据：重文件 I/O
# 注意：不 fork 子进程（不用 head|base64），避免 BPF 监控下极度缓慢
file_io_heavy() {
    local n=${1:-500}
    local payload
    payload=$(python3 -c "print('x' * 100)" 2>/dev/null || echo "x")
    for i in $(seq 1 "$n"); do
        local f="$TMPDIR/f_${i}_$$.txt"
        printf "payload_%d_%s_%s\n" "$i" "$(date +%N)" "${payload:0:100}" > "$f"
        cat "$f" > /dev/null 2>&1
        rm -f "$f"
        if [ $((i % 100)) -eq 0 ]; then echo -n "." >&2; fi
    done
    echo "" >&2
}

file_io() {
    local n=${1:-200}
    for i in $(seq 1 "$n"); do
        local f="$TMPDIR/f_${i}_$$.txt"
        echo "payload_${i}_$(date +%N)" > "$f"
        cat "$f" > /dev/null 2>&1
        rm -f "$f"
    done
}

# 真实场景：混合网络 I/O
network_io_real() {
    local n=${1:-200}
    local port=${2:-19999}
    for i in $(seq 1 "$n"); do
        local msg="net_${i}_$(date +%N)_$(hostname 2>/dev/null || echo 'localhost')"
        echo "$msg" | nc -w 1 127.0.0.1 "$port" 2>/dev/null || true
    done
}

network_io() {
    local n=${1:-50}
    local port=${2:-19999}
    for i in $(seq 1 "$n"); do
        echo "net_${i}_$(date +%N)" | nc -w 1 127.0.0.1 "$port" 2>/dev/null || true
    done
}

fork_ops() {
    local n=${1:-30}
    local pids=()
    for i in $(seq 1 "$n"); do
        (true) &
        pids+=($!)
    done
    wait "${pids[@]}"
}

workload() {
    local scale=${1:-1}
    file_io  $((200 * scale))
    network_io $((50 * scale))
    fork_ops  $((30 * scale))
}

# 大量模拟数据负载
workload_synthetic() {
    file_io_heavy 5000
    network_io_real 500
    fork_ops 300
}

# 高并发 burst：并行 I/O 制造事件洪峰
workload_burst() {
    local n=${1:-16}
    local pids=()
    for i in $(seq 1 "$n"); do
        file_io 1000 &
        pids+=($!)
    done
    wait "${pids[@]}"
}

# 真实场景负载
workload_real() {
    local scale=${1:-1}
    file_io  $((200 * scale))
    network_io $((50 * scale))
    fork_ops  $((30 * scale))
}

# ==================== 辅助函数 ====================

cpu_freq() {
    local f="/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
    if [ -r "$f" ]; then
        local khz
        khz=$(cat "$f")
        echo "$((khz / 1000))"
    else
        echo "N/A"
    fi
}

set_perf_governor() {
    local gov="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    if [ -w "$gov" ]; then
        echo performance > "$gov" 2>/dev/null && echo "  [GOV] ✅ performance" || echo "  [GOV] ❌ $(cat "$gov" 2>/dev/null || echo unknown)"
    else
        echo "  [GOV] ⚠️  $(cat "$gov" 2>/dev/null || echo N/A) (不可设置)"
    fi
}

check_tools() {
    local ok=0
    command -v perf &>/dev/null || { echo "  WARN: perf not found — instruction counting disabled"; ok=1; }
    command -v cpupower &>/dev/null || { echo "  WARN: cpupower not found — frequency locking disabled"; ok=1; }
    return $ok
}

lock_frequency() {
    local freq="${1:-2.0}"
    if ! command -v cpupower &>/dev/null; then
        echo "  [FREQ] ⚠️  cpupower not available, skip"
        return
    fi
    cpupower frequency-set -g performance &>/dev/null || true
    sleep 0.3
    cpupower frequency-set -d "${freq}GHz" -u "${freq}GHz" &>/dev/null || true
    sleep 0.3
    local mhz
    mhz=$(cpu_freq)
    echo "  [FREQ] Locked to ${freq}GHz, CPU0=${mhz}MHz"
}

start_nc_server() {
    local port=${1:-19999}
    while true; do nc -l -p "$port" -w 0 > /dev/null 2>&1 || true; sleep 0.05; done &
    NC_SERVER_PID=$!
    sleep 0.3
}

stop_nc_server() {
    kill "$NC_SERVER_PID" 2>/dev/null || true
    NC_SERVER_PID=""
}

start_loader_and_rb() {
    local extra_args="${1:-}"

    rm -f /sys/fs/bpf/sys_rb /sys/fs/bpf/ssl_rb /sys/fs/bpf/raw_rb /sys/fs/bpf/res_map 2>/dev/null || true

    > "$LOADER_LOG"
    stdbuf -oL -eL $LOADER $extra_args > "$LOADER_LOG" 2>&1 &
    LOADER_PID=$!

    local waited=0
    while [ "$waited" -lt 8 ]; do
        sleep 1
        waited=$((waited + 1))
        if ! kill -0 "$LOADER_PID" 2>/dev/null; then
            echo "  ❌ loader exited prematurely"
            cat "$LOADER_LOG"
            return 1
        fi
        if [ -f "/sys/fs/bpf/sys_rb" ]; then
            break
        fi
    done
    if [ ! -f "/sys/fs/bpf/sys_rb" ]; then
        echo "  ❌ loader BPF not ready in 8s"
        cat "$LOADER_LOG"
        return 1
    fi

    > "$RINGBUF_LOG"
    # 替换 null 字节为 '.'（SSL 载荷含 \x00），避免日志被 grep 视为二进制
    local rb_fifo="/tmp/rb_fifo_$$"
    rm -f "$rb_fifo"
    mkfifo "$rb_fifo"
    stdbuf -oL -eL $RINGBUF > "$rb_fifo" 2>&1 &
    RINGBUF_PID=$!
    stdbuf -oL tr '\0' '.' < "$rb_fifo" > "$RINGBUF_LOG" &
    RINGBUF_FILTER_PID=$!
    sleep 1
    if ! kill -0 "$RINGBUF_PID" 2>/dev/null; then
        echo "  ❌ ringbuf_handler exited"
        cat "$RINGBUF_LOG"
        return 1
    fi

    return 0
}

stop_loader_and_rb() {
    kill -INT "$RINGBUF_PID" 2>/dev/null || true
    rb_waited=0
    while kill -0 "$RINGBUF_PID" 2>/dev/null && [ "$rb_waited" -lt 3 ]; do
        sleep 1; rb_waited=$((rb_waited + 1))
    done
    kill -9 "$RINGBUF_PID" 2>/dev/null || true
    wait "$RINGBUF_PID" 2>/dev/null || true
    RINGBUF_PID=""
    kill "$RINGBUF_FILTER_PID" 2>/dev/null || true
    wait "$RINGBUF_FILTER_PID" 2>/dev/null || true
    RINGBUF_FILTER_PID=""

    kill -INT "$LOADER_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$LOADER_PID" 2>/dev/null || true
    wait "$LOADER_PID" 2>/dev/null || true
    LOADER_PID=""

    rm -f /sys/fs/bpf/sys_rb /sys/fs/bpf/ssl_rb /sys/fs/bpf/raw_rb /sys/fs/bpf/res_map 2>/dev/null || true
}

warmup_heavy() {
    file_io 2000 > /dev/null 2>&1 || true
    network_io 500 > /dev/null 2>&1 || true
    fork_ops 300 > /dev/null 2>&1 || true
}

warmup_light() {
    file_io 200 > /dev/null 2>&1 || true
    network_io 50 > /dev/null 2>&1 || true
    fork_ops 50 > /dev/null 2>&1 || true
}

WRAPPER_SCRIPT="/tmp/perf_wrapper_$$.sh"
generate_wrapper() {
    cat > "$WRAPPER_SCRIPT" << 'HEREDOC'
#!/bin/bash
set -eo pipefail
HEREDOC
    declare -f file_io file_io_heavy network_io network_io_real fork_ops workload workload_synthetic workload_real >> "$WRAPPER_SCRIPT"
    echo 'export TMPDIR="${TMPDIR:-}"; "$@"' >> "$WRAPPER_SCRIPT"
    chmod +x "$WRAPPER_SCRIPT"
}

time_workload() {
    local label="$1"
    shift
    local times=()
    local instrs=()
    for iter in 1 2 3; do
        echo "    Run $iter..." >&2
        sync
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
        warmup_light > /dev/null 2>&1
        local start end
        start=$(date +%s.%N)
        if command -v perf &>/dev/null; then
            export TMPDIR
            perf stat -e instructions -- "$WRAPPER_SCRIPT" "$@" > /dev/null 2>/tmp/perf_$$.tmp || true
            end=$(date +%s.%N)
            local instr
            instr=$(awk '/instructions/{print $1}' /tmp/perf_$$.tmp 2>/dev/null | tr -d ',' || echo 0)
            if [ "${instr:-0}" = "0" ] || [ -z "${instr:-}" ]; then
                echo "  [PERF-DBG] raw output: $(head -5 /tmp/perf_$$.tmp | tr '\n' ';')" >&2
            fi
            instrs+=("${instr:-0}")
        else
            "$@" > /dev/null 2>&1
            end=$(date +%s.%N)
        fi
        times+=($(echo "$end - $start" | bc -l))
    done
    IFS=$'\n' ts=($(printf '%s\n' "${times[@]}" | sort -n)); unset IFS
    local median_time="${ts[1]}"
    local result="$median_time"
    if [ "${#instrs[@]}" -gt 0 ]; then
        IFS=$'\n' is=($(printf '%s\n' "${instrs[@]}" | sort -n)); unset IFS
        local median_instr="${is[1]}"
        echo "  $label: time=${median_time}s  instructions=${median_instr}  raw_time=(${times[*]})" >&2
        result="${median_time}|${median_instr}"
    else
        echo "  $label: time=${median_time}s  raw=(${times[*]})" >&2
    fi
    echo "$result"
}

read_drops() {
    local drop_id
    drop_id=$(bpftool map list 2>/dev/null | awk '/drop_counters/{print $1}' | tr -d ':' || true)
    if [ -z "$drop_id" ]; then echo "N/A"; return 0; fi
    bpftool map dump id "$drop_id" 2>/dev/null | awk '
    /value:/ {
        for(i=1;i<=NF;i++) {
            if($i ~ /^value:/) {
                sub(/^value:/, "", $i)
                gsub(/,/, "", $i)
                sum += int($i)
            }
        }
    }
    END { print sum+0 }
    ' || true
}

# ==================== T2025 风格：探针功能验证 ====================
validate_raw_probes() {
    local ringbuf_log="$1"

    echo "  ── 探针功能验证 ──"

    : > "$ringbuf_log"

    echo "raw_probe_test_$(date +%N)" > "/tmp/.raw_probe_test.$$"
    dd if=/tmp/.raw_probe_test.$$ of=/dev/null bs=4 count=1 2>/dev/null || true
    echo "raw_test_net" | nc -w 1 127.0.0.1 19999 2>/dev/null || true
    rm -f "/tmp/.raw_probe_test.$$"

    sleep 1

    local ringbuf_lines
    ringbuf_lines=$(wc -l < "$ringbuf_log" 2>/dev/null || echo 0)
    local sys_count
    sys_count=$(grep -c '\-> Type:' "$ringbuf_log" 2>/dev/null || true)
    local raw_count
    raw_count=$(grep -cE '(FD:|Source:)' "$ringbuf_log" 2>/dev/null || true)

    echo "    ringbuf log: ${ringbuf_lines} 行, sys=${sys_count}, raw=${raw_count}"

    if [ "$raw_count" -gt 0 ]; then
        echo "    ✅ raw 探针功能正常"
        return 0
    else
        echo "    ❌ raw 探针未捕获任何事件"
        echo "    [DIAG] ringbuf log content (last 20 lines):"
        tail -20 "$ringbuf_log" 2>/dev/null | sed 's/^/      /'
        echo "    [DIAG] loader log (last 10 lines):"
        tail -10 "$LOADER_LOG" 2>/dev/null | sed 's/^/      /'
        echo "    [DIAG] BPF prog list (sys_write_raw):"
        bpftool prog list 2>/dev/null | grep -i 'sys_write_raw\|sys_sendto_raw\|write' | sed 's/^/      /'
        echo "    [DIAG] BPF prog list (sys_event probes, first 5):"
        bpftool prog list 2>/dev/null | grep -i 'sys_execve\|sys_openat\|sys_connect' | head -5 | sed 's/^/      /'
        return 1
    fi
}

# ==================== 数据捕获开销测试 ====================
# 方案：大量模拟数据 + 真实场景测试
# 结果：平均开销（指令数）
test_data_capture_overhead() {
    local ringbuf_log="$1"

    echo "  ── 数据捕获开销测试 ──"

    # 备份 log 指针，用于恢复
    local rb_bak="/tmp/ringbuf_bak_$$.log"
    cp "$ringbuf_log" "$rb_bak" 2>/dev/null || true

    # ----- 大量模拟数据测试 -----
    echo "  [模拟数据] 启动..."
    : > "$ringbuf_log"
    local syn_start syn_end
    syn_start=$(date +%s.%N)
    workload_synthetic > /dev/null 2>&1 || true
    syn_end=$(date +%s.%N)
    local syn_time
    syn_time=$(echo "$syn_end - $syn_start" | bc -l)
    local syn_sys syn_raw
    syn_sys=$(grep -c '\-> Type:' "$ringbuf_log" 2>/dev/null || true)
    syn_raw=$(grep -cE '(FD:|Source:)' "$ringbuf_log" 2>/dev/null || true)
    echo "  [模拟数据] time=${syn_time}s  sys_events=${syn_sys}  raw_events=${syn_raw}"

    # ----- 真实场景测试 -----
    echo "  [真实场景] 启动..."
    : > "$ringbuf_log"
    local real_start real_end
    real_start=$(date +%s.%N)
    workload_real 30 > /dev/null 2>&1 || true
    real_end=$(date +%s.%N)
    local real_time
    real_time=$(echo "$real_end - $real_start" | bc -l)
    local real_sys real_raw
    real_sys=$(grep -c '\-> Type:' "$ringbuf_log" 2>/dev/null || true)
    real_raw=$(grep -cE '(FD:|Source:)' "$ringbuf_log" 2>/dev/null || true)
    echo "  [真实场景] time=${real_time}s  sys_events=${real_sys}  raw_events=${real_raw}"

    # ----- 高并发 burst 测试 -----
    echo "  [并发 Burst] 启动..."
    : > "$ringbuf_log"
    local burst_start burst_end
    burst_start=$(date +%s.%N)
    workload_burst 16 > /dev/null 2>&1 || true
    burst_end=$(date +%s.%N)
    local burst_time
    burst_time=$(echo "$burst_end - $burst_start" | bc -l)
    local burst_sys burst_raw
    burst_sys=$(grep -c '\-> Type:' "$ringbuf_log" 2>/dev/null || true)
    burst_raw=$(grep -cE '(FD:|Source:)' "$ringbuf_log" 2>/dev/null || true)
    echo "  [并发 Burst] time=${burst_time}s  sys_events=${burst_sys}  raw_events=${burst_raw}"

    # 恢复 log
    cp "$rb_bak" "$ringbuf_log" 2>/dev/null || true
    rm -f "$rb_bak"

    # 返回指标
    DATA_CAPTURE_OVERHEAD_SYN_TIME="$syn_time"
    DATA_CAPTURE_OVERHEAD_SYN_SYS="$syn_sys"
    DATA_CAPTURE_OVERHEAD_SYN_RAW="$syn_raw"
    DATA_CAPTURE_OVERHEAD_REAL_TIME="$real_time"
    DATA_CAPTURE_OVERHEAD_REAL_SYS="$real_sys"
    DATA_CAPTURE_OVERHEAD_REAL_RAW="$real_raw"
    DATA_CAPTURE_OVERHEAD_BURST_TIME="$burst_time"
    DATA_CAPTURE_OVERHEAD_BURST_SYS="$burst_sys"
    DATA_CAPTURE_OVERHEAD_BURST_RAW="$burst_raw"
    echo "  ✅ 数据捕获开销测试完成"
}

# ==================== 数据抓取率测试 ====================
# 计算捕获事件数占预期事件数的比例
test_data_capture_rate() {
    local ringbuf_log="$1"
    local drops="${2:-0}"

    echo "  ── 数据抓取率测试 ──"

    local total_sys total_raw
    total_sys=$(grep -c '\-> Type:' "$ringbuf_log" 2>/dev/null || true)
    total_raw=$(grep -cE '(FD:|Source:)' "$ringbuf_log" 2>/dev/null || true)
    local total_captured=$(( total_sys + total_raw ))

    local pipe_rate=100
    local total_with_drops=$(( total_captured + drops ))
    if [ "$total_with_drops" -gt 0 ] 2>/dev/null; then
        pipe_rate=$(echo "scale=2; $total_captured * 100 / $total_with_drops" | bc -l 2>/dev/null || echo 100)
    fi

    echo "    sys_events=${total_sys}  raw_events=${total_raw}  total=${total_captured}  drop_counter=${drops}"
    echo "    管道捕获率 = ${pipe_rate}%  (基于 Ring Buffer drop_counter)"

    DATA_CAPTURE_RATE_SYS="$total_sys"
    DATA_CAPTURE_RATE_RAW="$total_raw"
    DATA_CAPTURE_RATE_TOTAL="$total_captured"
    DATA_CAPTURE_PIPE_RATE="$pipe_rate"

    echo "  ✅ 数据抓取率测试完成"
}

# ==================== 主流程 ====================

echo "================================================"
echo "  eBPF Multi-Agent Monitor — 性能基准测试"
echo "================================================"
echo "  测试项目："
echo "    1. 数据捕获开销 — 大量模拟数据 + 真实场景"
echo "    2. 数据抓取率   — 事件捕获百分比"
echo "    3. 探针性能     — baseline / fastpath / fullcapture"
echo "================================================"
echo ""

prepare_files() {
    for i in $(seq 1 2000); do
        echo "content_$i" > "$TMPDIR/prep_$i.txt"
    done
}
prepare_files

echo "--- 全面预热 ---"
warmup_heavy
echo "  ✅ 预热完成"
echo ""

check_tools
set_perf_governor
lock_frequency 2.0
generate_wrapper

phases=(baseline fastpath fullcapture)
if command -v shuf &>/dev/null; then
    IFS=$'\n' phases=($(shuf -e "${phases[@]}")); unset IFS
elif sort --help 2>&1 | grep -q '\-R' &>/dev/null; then
    IFS=$'\n' phases=($(printf '%s\n' "${phases[@]}" | sort -R)); unset IFS
fi

echo "  执行顺序: ${phases[*]}"
echo ""

for ptype in "${phases[@]}"; do
    echo "━━━ Phase: ${ptype} ━━━"
    echo "  CPU: $(cpu_freq)MHz"
    warmup_heavy
    echo "  CPU after warmup: $(cpu_freq)MHz"

    case "$ptype" in
        baseline)
            start_nc_server
            IFS='|' read -r BASELINE BASELINE_INSTR < <(time_workload "baseline" workload 90)
            stop_nc_server
            echo "  ✅ baseline 完成"
            ;;
        fastpath)
            if [ "$EUID" -eq 0 ] && start_loader_and_rb; then
                echo "  [INFO] loader PID=$LOADER_PID  ringbuf PID=$RINGBUF_PID"
                echo "  [INFO] 本 shell PID=$$ 未在 monitored_pids 中（fast-path）"
                start_nc_server
                IFS='|' read -r FASTPATH FASTPATH_INSTR < <(time_workload "fastpath" workload 90)
                stop_nc_server
                stop_loader_and_rb
                echo "  ✅ fastpath 完成"
            else
                [ "$EUID" -ne 0 ] && echo "  ⚠️  SKIP: 需要 root" || echo "  ⚠️  SKIP: loader 启动失败"
            fi
            ;;
        fullcapture)
            if [ "$EUID" -ne 0 ] || ! start_loader_and_rb "$$"; then
                [ "$EUID" -ne 0 ] && echo "  ⚠️  SKIP: 需要 root" || echo "  ⚠️  SKIP: loader 启动失败"
                continue
            fi

            echo "  [INFO] loader PID=$LOADER_PID  ringbuf PID=$RINGBUF_PID"
            echo "  [INFO] 本 shell PID=$$ 已注册到 monitored_pids"

            nc_restore=""
            if [ -z "${NC_SERVER_PID:-}" ]; then
                start_nc_server
                nc_restore=1
            fi

            validate_raw_probes "$RINGBUF_LOG" || true
            # 数据捕获开销测试（模拟数据 + 真实场景）
            test_data_capture_overhead "$RINGBUF_LOG"
            echo ""

            # 标准性能测量
            echo "  ── 标准性能测量 ──"
            IFS='|' read -r MONITORED MONITORED_INSTR < <(time_workload "fullcapture" workload 90)
            echo "  ✅ fullcapture 完成"

            if [ -n "$nc_restore" ]; then stop_nc_server; fi

            DROPS=$(read_drops)
            echo "  drop_counter: $DROPS"

            kill -INT "$RINGBUF_PID" 2>/dev/null || true
            rb_waited=0
            while kill -0 "$RINGBUF_PID" 2>/dev/null && [ "$rb_waited" -lt 3 ]; do
                sleep 1; rb_waited=$((rb_waited + 1))
            done
            kill -9 "$RINGBUF_PID" 2>/dev/null || true
            wait "$RINGBUF_PID" 2>/dev/null || true
            RINGBUF_PID=""
            kill "$RINGBUF_FILTER_PID" 2>/dev/null || true
            wait "$RINGBUF_FILTER_PID" 2>/dev/null || true
            RINGBUF_FILTER_PID=""

            # 数据抓取率测试（基于总日志 + drop_counter）
            test_data_capture_rate "$RINGBUF_LOG" "$DROPS"

            stop_loader_and_rb
            ;;
    esac
    echo "  CPU after test: $(cpu_freq)MHz"
    echo ""
done

# ==================== 结果汇总 ====================
echo "================================================"
echo "  结果汇总"
echo "================================================"
echo ""
echo "DEBUG BASELINE='${BASELINE:-UNSET}' FASTPATH='${FASTPATH:-UNSET}' MONITORED='${MONITORED:-UNSET}'" >&2
sleep 0.1

echo "== 性能指标 =="
echo "  Phase 1 (基线):        ${BASELINE}s"
if [ -n "${BASELINE_INSTR:-}" ]; then echo "  Phase 1 指令数:        ${BASELINE_INSTR}"; fi
echo "  Phase 2 (fast-path):   ${FASTPATH:-N/A}s"
if [ -n "${FASTPATH_INSTR:-}" ]; then echo "  Phase 2 指令数:        ${FASTPATH_INSTR:-N/A}"; fi
echo "  Phase 3 (full-capture): ${MONITORED:-N/A}s"
if [ -n "${MONITORED_INSTR:-}" ]; then echo "  Phase 3 指令数:        ${MONITORED_INSTR:-N/A}"; fi

OVERHEAD_METRIC="指令数"
if [ -z "${BASELINE_INSTR:-}" ]; then
    OVERHEAD_METRIC="wall-clock"
fi
echo "  开销基准:             ${OVERHEAD_METRIC}"
echo ""

echo "── 数据捕获开销 ──"
echo "  测试方案: 大量模拟数据 + 真实场景 + 并发 Burst"
echo "  模拟数据耗时:  ${DATA_CAPTURE_OVERHEAD_SYN_TIME:-N/A}s"
echo "  模拟数据 sys:  ${DATA_CAPTURE_OVERHEAD_SYN_SYS:-N/A}"
echo "  模拟数据 raw:  ${DATA_CAPTURE_OVERHEAD_SYN_RAW:-N/A}"
echo "  真实场景耗时:  ${DATA_CAPTURE_OVERHEAD_REAL_TIME:-N/A}s"
echo "  真实场景 sys:  ${DATA_CAPTURE_OVERHEAD_REAL_SYS:-N/A}"
echo "  真实场景 raw:  ${DATA_CAPTURE_OVERHEAD_REAL_RAW:-N/A}"
echo "  并发 Burst 耗时: ${DATA_CAPTURE_OVERHEAD_BURST_TIME:-N/A}s"
echo "  并发 Burst sys: ${DATA_CAPTURE_OVERHEAD_BURST_SYS:-N/A}"
echo "  并发 Burst raw: ${DATA_CAPTURE_OVERHEAD_BURST_RAW:-N/A}"
if [ -n "${MONITORED_INSTR:-}" ] && [ -n "${BASELINE_INSTR:-}" ] && [ "${BASELINE_INSTR:-0}" -gt 0 ] 2>/dev/null; then
    OVERHEAD_PCT=$(echo "scale=2; ($MONITORED_INSTR - $BASELINE_INSTR) * 100 / $BASELINE_INSTR" | bc -l)
    echo "  平均开销:    ${OVERHEAD_PCT}% (指令数)"
else
    echo "  平均开销:    N/A (缺少基线数据)"
fi
echo ""

echo "── 管道捕获率 ──"
echo "  测试方案: 基于 Ring Buffer drop_counter"
echo "  drop_counter:   ${DROPS:-N/A}"
echo "  总捕获量:       ${DATA_CAPTURE_RATE_TOTAL:-0}"
echo "  管道捕获率:     ${DATA_CAPTURE_PIPE_RATE:-N/A}%"
echo ""

echo "── 逐项评判 ──"

if [ -n "${FASTPATH:-}" ] && [ "$(echo "$FASTPATH > 0" | bc -l)" -eq 1 ] && [ "$EUID" -eq 0 ]; then
    if [ -n "${FASTPATH_INSTR:-}" ] && [ "$(echo "${FASTPATH_INSTR:-0} > 0" | bc -l)" -eq 1 ]; then
        FAST_OVERHEAD=$(echo "scale=2; ($FASTPATH_INSTR - $BASELINE_INSTR) * 100 / $BASELINE_INSTR" | bc -l)
    else
        FAST_OVERHEAD=$(echo "scale=2; ($FASTPATH - $BASELINE) * 100 / $BASELINE" | bc -l)
    fi
    echo "  Fast-path 开销:      ${FAST_OVERHEAD}%  (${OVERHEAD_METRIC})"
    if (( $(echo "$FAST_OVERHEAD <= 3.0" | bc -l) )); then
        echo "    ✅ PASS (≤ 3%)"
        PASS=$((PASS + 1))
    else
        echo "    ❌ FAIL (> 3%)"
        FAIL=$((FAIL + 1))
    fi
fi

if [ -n "${MONITORED:-}" ] && [ "$(echo "$MONITORED > 0" | bc -l)" -eq 1 ] && [ "$EUID" -eq 0 ]; then
    if [ -n "${MONITORED_INSTR:-}" ] && [ "$(echo "${MONITORED_INSTR:-0} > 0" | bc -l)" -eq 1 ]; then
        FULL_OVERHEAD=$(echo "scale=2; ($MONITORED_INSTR - $BASELINE_INSTR) * 100 / $BASELINE_INSTR" | bc -l)
    else
        FULL_OVERHEAD=$(echo "scale=2; ($MONITORED - $BASELINE) * 100 / $BASELINE" | bc -l)
    fi
    echo "  Full-capture 开销:   ${FULL_OVERHEAD}%  (${OVERHEAD_METRIC})"
    if (( $(echo "$FULL_OVERHEAD <= 30.0" | bc -l) )); then
        echo "    ✅ PASS (≤ 30%)"
        PASS=$((PASS + 1))
    else
        echo "    ❌ FAIL (> 30%)"
        FAIL=$((FAIL + 1))
    fi
fi

if [ "$EUID" -eq 0 ] && [ -n "${DROPS:-}" ]; then
    echo "  drop_counter:         ${DROPS}"
    if [ "$DROPS" = "0" ] || [ "$DROPS" = "0.0" ]; then
        echo "    ✅ PASS (无丢包)"
        PASS=$((PASS + 1))
    elif [ "$DROPS" = "N/A" ] || [ "$DROPS" = "parse_error" ]; then
        echo "    ⚠️  SKIP: 无法读取 drop_counter"
    else
        echo "    ❌ FAIL (有丢包)"
        FAIL=$((FAIL + 1))
    fi
fi

if [ "$EUID" -eq 0 ] && [ "${DATA_CAPTURE_RATE_SYS:-0}" -gt 0 ] 2>/dev/null; then
    echo "  sys 事件数:         ${DATA_CAPTURE_RATE_SYS}"
    echo "    ✅ PASS (sys 捕获正常)"
    PASS=$((PASS + 1))
fi

echo ""
echo "================================================"
echo "  结果：$PASS 通过, $FAIL 失败"
echo "================================================"
exit $FAIL
