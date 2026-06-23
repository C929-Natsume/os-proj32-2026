# Showcase Backend

This backend reads real monitor outputs from:

- `/mnt/e/os2026/ebpf-multi-agent-monitor/logs/alerts/analysis.db`
- `/mnt/e/os2026/ebpf-multi-agent-monitor/src/config/app_config.yaml`

It is read-only. It does not modify the main monitor project.

## Install

```bash
cd /mnt/e/os2026/ebpf-monitor-showcase/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
cd /mnt/e/os2026/ebpf-monitor-showcase/backend
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload
```

## Optional environment variables

```bash
export MONITOR_PROJECT_ROOT=/mnt/e/os2026/ebpf-multi-agent-monitor
export MONITOR_SQLITE_PATH=/mnt/e/os2026/ebpf-multi-agent-monitor/logs/alerts/analysis.db
```
