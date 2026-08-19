#!/bin/bash
# Workload functions for the eBPF perf benchmark.
# Mirrors the original test/test_perf.sh workload functions.
# The workload runs in a bash subprocess so comm=bash (not matched by
# the kernel try_auto_register, unlike python).

FILE_IO_N=${FILE_IO_N:-200}
NET_N=${NET_N:-50}
FORK_N=${FORK_N:-30}
NET_PORT=${NET_PORT:-19999}
TMPDIR=${TMPDIR:-/tmp/perf_bench_wl}

mkdir -p "$TMPDIR"

file_io() {
    local n=${1:-$FILE_IO_N}
    local i
    for ((i=1; i<=n; i++)); do
        local f="$TMPDIR/f_${i}_$$.txt"
        printf "payload_%d_%s\n" "$i" "$(date +%N)" > "$f"
        cat "$f" > /dev/null 2>&1
        rm -f "$f"
    done
}

file_io_heavy() {
    local n=${1:-500}
    local payload="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    local i
    for ((i=1; i<=n; i++)); do
        local f="$TMPDIR/f_${i}_$$.txt"
        printf "payload_%d_%s_%s\n" "$i" "$(date +%N)" "${payload:0:100}" > "$f"
        cat "$f" > /dev/null 2>&1
        rm -f "$f"
    done
}

network_io() {
    local n=${1:-$NET_N}
    local port=${2:-$NET_PORT}
    local i
    for ((i=1; i<=n; i++)); do
        echo "net_${i}_$(date +%N)" | nc -w 1 127.0.0.1 "$port" 2>/dev/null || true
    done
}

network_io_real() {
    local n=${1:-200}
    local port=${2:-$NET_PORT}
    local i
    for ((i=1; i<=n; i++)); do
        local msg="net_${i}_$(date +%N)_$(hostname 2>/dev/null || echo 'localhost')"
        echo "$msg" | nc -w 1 127.0.0.1 "$port" 2>/dev/null || true
    done
}

fork_ops() {
    local n=${1:-$FORK_N}
    local i
    local -a pids=()
    for ((i=1; i<=n; i++)); do
        (true) &
        pids+=($!)
    done
    wait "${pids[@]}" 2>/dev/null || true
}

workload() {
    local scale=${1:-1}
    local file_n=$((FILE_IO_N * scale))
    local net_n=$((NET_N * scale))
    local fork_n=$((FORK_N * scale))
    file_io "$file_n"
    network_io "$net_n" "$NET_PORT"
    fork_ops "$fork_n"
}

workload_synthetic() {
    file_io_heavy 500
    network_io_real 200
    fork_ops 100
}

workload_burst() {
    local n=${1:-8}
    local i
    local -a pids=()
    for ((i=1; i<=n; i++)); do
        file_io 200 &
        pids+=($!)
    done
    wait "${pids[@]}" 2>/dev/null || true
}

# Dispatch: bash wrapper.sh <fn> [args...]
FUNC="$1"
shift || true
case "$FUNC" in
    file_io|file_io_heavy|network_io|network_io_real|fork_ops|workload|workload_synthetic|workload_burst)
        "$FUNC" "$@"
        ;;
    *)
        echo "Unknown workload fn: $FUNC" >&2
        exit 1
        ;;
esac
