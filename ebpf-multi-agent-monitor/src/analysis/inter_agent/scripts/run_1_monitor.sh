#!/bin/bash
set -eo pipefail
PROJ=~/ebpf-multi-agent-monitor
SCRIPTS=$PROJ/src/analysis/inter_agent/scripts
CFG=$PROJ/src/analysis/inter_agent/config/default.yaml

# API key is read from config/default.yaml → llm.api_key
rm -f runtime.log
python -u vm_runtime_collector.py --topology hierarchical --rounds 10 --num-agents 4 --sleep 5 2>&1 | tee runtime.log

echo ""
echo "=== Results ==="
grep -E "Collection|Detected" runtime.log | tail -3
echo ""
echo "=== Logs ==="
ls -la $PROJ/logs/inter_log/ 2>/dev/null
cat $PROJ/logs/inter_log/anomaly_*.log 2>/dev/null | head -30 || echo "no anomalies"
cd $SCRIPTS