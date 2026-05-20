#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONITOR_DIR="${ROOT_DIR}/monitor"
MONITOR_BIN="${MONITOR_DIR}/monitor"

WORKSPACE="${MONITOR_WORKSPACE:-${ROOT_DIR}}"
RULES="${MONITOR_AUDIT_RULES:-${ROOT_DIR}/intra_agent/audit_rules.conf}"
JUDGE="${MONITOR_LLM_JUDGE_CMD:-${ROOT_DIR}/intra_agent/llm_judge.sh}"

LOG_FILE="/tmp/intra_agent_demo_$(date +%Y%m%d_%H%M%S).log"
CLAUDE_SHELL="/tmp/claude-shell"
MONITOR_PID=""
MONITOR_LAUNCHER="sudo"

setup_privilege() {
  if [[ "${EUID}" -eq 0 ]]; then
    MONITOR_LAUNCHER=""
    echo "[demo] 当前以 root 身份运行（sudo ./intra_agent/run_demo.sh）"
    return
  fi

  echo "[demo] 预先进行一次 sudo 认证（sudo -v）..."
  sudo -v
  MONITOR_LAUNCHER="sudo"
}

run_privileged() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

ensure_bpffs() {
  if mountpoint -q /sys/fs/bpf; then
    return
  fi
  echo "[demo] 检测到 bpffs 未挂载，正在挂载 /sys/fs/bpf ..."
  run_privileged mkdir -p /sys/fs/bpf
  run_privileged mount -t bpf bpf /sys/fs/bpf
}

cleanup() {
  local i
  if [[ -z "${MONITOR_PID}" ]]; then
    return
  fi

  if kill -0 "${MONITOR_PID}" 2>/dev/null; then
    if [[ "${EUID}" -eq 0 ]]; then
      kill -TERM "${MONITOR_PID}" >/dev/null 2>&1 || true
    else
      sudo -n kill -TERM "${MONITOR_PID}" >/dev/null 2>&1 || true
    fi
  fi

  # wait up to ~2s for graceful exit
  for i in $(seq 1 20); do
    if ! kill -0 "${MONITOR_PID}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  # force kill if still alive
  if kill -0 "${MONITOR_PID}" 2>/dev/null; then
    if [[ "${EUID}" -eq 0 ]]; then
      kill -KILL "${MONITOR_PID}" >/dev/null 2>&1 || true
    else
      sudo -n kill -KILL "${MONITOR_PID}" >/dev/null 2>&1 || true
    fi
  fi

  wait "${MONITOR_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "[demo] 工作目录: ${WORKSPACE}"
echo "[demo] 规则文件: ${RULES}"
echo "[demo] 复核脚本: ${JUDGE}"
echo "[demo] 日志文件: ${LOG_FILE}"

setup_privilege
ensure_bpffs

if [[ ! -x "${MONITOR_BIN}" ]]; then
  echo "[demo] 未发现 monitor 可执行文件，正在编译..."
  make -C "${MONITOR_DIR}" -j4
fi

echo "[demo] 正在创建 claude 模拟 shell: ${CLAUDE_SHELL}"
cp /bin/bash "${CLAUDE_SHELL}"
chmod +x "${CLAUDE_SHELL}"

if [[ -n "${MONITOR_LAUNCHER}" ]]; then
  echo "[demo] 正在启动 monitor（需要 sudo）..."
  sudo env \
    MONITOR_WORKSPACE="${WORKSPACE}" \
    MONITOR_AUDIT_RULES="${RULES}" \
    MONITOR_LLM_JUDGE_CMD="${JUDGE}" \
    MONITOR_DEMO_ALL=1 \
    "${MONITOR_BIN}" >"${LOG_FILE}" 2>&1 &
else
  echo "[demo] 正在启动 monitor..."
  env \
    MONITOR_WORKSPACE="${WORKSPACE}" \
    MONITOR_AUDIT_RULES="${RULES}" \
    MONITOR_LLM_JUDGE_CMD="${JUDGE}" \
    MONITOR_DEMO_ALL=1 \
    "${MONITOR_BIN}" >"${LOG_FILE}" 2>&1 &
fi
MONITOR_PID=$!

sleep 2
if ! kill -0 "${MONITOR_PID}" 2>/dev/null; then
  echo "[demo] monitor 启动失败，请检查日志: ${LOG_FILE}"
  exit 1
fi

run_case() {
  local title="$1"
  local cmd="$2"
  echo "[demo] 用例: ${title}"
  "${CLAUDE_SHELL}" -c "${cmd}" || true
  sleep 1
}

# 尽量使用 shell 内建能力，确保操作留在 claude 模拟进程内。
run_case "敏感文件读取（内建重定向）" "while IFS= read -r _; do break; done < /etc/passwd"
run_case "工作区外写入（内建重定向）" ": > /home/${USER}/agent_demo_out_demo.txt"
run_case "嵌套 Shell 执行" "/bin/bash -c 'echo nested shell exec >/dev/null'"

sleep 2
cleanup
MONITOR_PID=""

echo
echo "[demo] ===== Intra 审计高亮 ====="
HIGHLIGHT_LINES="$(grep -E "\[请求\]\[单体审计\]|\[告警\]\[单体审计\]" "${LOG_FILE}" | tail -n 120 || true)"
if [[ -n "${HIGHLIGHT_LINES}" ]]; then
  echo "${HIGHLIGHT_LINES}"
else
  echo "[demo] 未捕获到 请求/告警，以下展示原始监控日志末尾用于排查："
  tail -n 80 "${LOG_FILE}" || true
fi

echo
echo "[demo] ===== 告警汇总 ====="
grep -oE "\[告警\]\[单体审计\]\[[^]]+\]" "${LOG_FILE}" | sort | uniq -c || true

echo
echo "[demo] 演示结束，完整日志: ${LOG_FILE}"
