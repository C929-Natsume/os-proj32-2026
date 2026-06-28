#!/bin/bash
set -eo pipefail
PROJ=~/ebpf-multi-agent-monitor
SCRIPTS=$PROJ/src/analysis/inter_agent/scripts
CFG=$PROJ/src/analysis/inter_agent/config/default.yaml
USR=$PROJ/src/user
echo "=== [Run 3] Large-scale Mixed Demo (stored data) ==="
echo "100 rounds, 20% inject, no eBPF needed"

python -u demo_large_scale.py --stored --rounds 100 --inject-rate 0.20 2>&1

echo ""
echo "=== Logs ==="
ls -la $PROJ/logs/inter_log/ 2>/dev/null
cat $PROJ/logs/inter_log/anomaly_*.log 2>/dev/null | head -60 || echo "no anomalies"
cd $SCRIPTS