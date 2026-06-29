#!/bin/bash
set -e
PROJ=~/ebpf-multi-agent-monitor
SCRIPTS=$PROJ/src/analysis/inter_agent/scripts
CFG=$PROJ/src/analysis/inter_agent/config/default.yaml

# API key is read from config/default.yaml → llm.api_key
python -u demo_all_anomalies.py --stored 2>&1

echo ""
echo "=== Logs ==="
ls -la $PROJ/logs/inter_log/ 2>/dev/null
cat $PROJ/logs/inter_log/anomaly_*.log 2>/dev/null | head -50 || echo "no anomalies"
cd $SCRIPTS