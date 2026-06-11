#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_DIR="$ROOT_DIR/src/user"
BPFTOOL_BIN="${BPFTOOL_BIN:-/mnt/e/os2026/bpftool/src/bpftool}"

make -C "$USER_DIR" loader BPFTOOL="$BPFTOOL_BIN"

sudo bash -lc "
set -euo pipefail
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug || true
mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing || true
cd '$USER_DIR'
ulimit -l unlimited
exec ./loader
"
