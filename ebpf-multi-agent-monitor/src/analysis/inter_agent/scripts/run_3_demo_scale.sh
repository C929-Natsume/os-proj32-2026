#!/bin/bash
set -e
PROJ=~/ebpf-multi-agent-monitor
SCRIPTS=$PROJ/src/analysis/inter_agent/scripts
USR=$PROJ/src/user
echo "=== [Run 3] Large-scale Mixed Demo ==="
echo "eBPF + 100 rounds, 20% inject"

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
python -u demo_large_scale.py --live --rounds 100 --inject-rate 0.20 2>&1

echo ""
echo "=== Logs ==="
ls -la $PROJ/logs/inter_log/ 2>/dev/null
cat $PROJ/logs/inter_log/anomaly_*.log 2>/dev/null | head -60 || echo "no anomalies"
cd $SCRIPTS