#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_DIR="$ROOT_DIR/src/user"
BPFTOOL_BIN="${BPFTOOL_BIN:-/mnt/e/os2026/bpftool/src/bpftool}"

make -C "$USER_DIR" ringbuf_handler BPFTOOL="$BPFTOOL_BIN"

cd "$USER_DIR"
exec ./ringbuf_handler
