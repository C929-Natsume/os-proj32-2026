#!/bin/bash
set -e
PROJ=~/ebpf-multi-agent-monitor
SCRIPTS=$PROJ/src/analysis/inter_agent/scripts
USR=$PROJ/src/user
echo "=== [Run 2] All 19 Anomaly Types Demo ==="
echo "eBPF + injecting all anomaly types"

sudo mkdir -p /sys/fs/bpf 2>/dev/null || true
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
cd $USR
sudo pkill -f loader 2>/dev/null || true
sudo pkill -f ringbuf_handler 2>/dev/null || true
sleep 1
sudo ./loader > /dev/null 2>&1 &
echo "loader PID=$!"
sleep 1
sudo ./ringbuf_handler > /dev/null 2>&1 &
echo "ringbuf PID=$!"
sleep 2

cd $SCRIPTS
source ~/autogen_sandbox/venv_autogen/bin/activate
: "${SILICONFLOW_API_KEY:?Error: SILICONFLOW_API_KEY environment variable not set}"
python -u demo_all_anomalies.py --live 2>&1

echo ""
echo "=== Logs ==="
ls -la $PROJ/logs/inter_log/ 2>/dev/null
cat $PROJ/logs/inter_log/anomaly_*.log 2>/dev/null | head -50 || echo "no anomalies"
cd $SCRIPTS