from pathlib import Path
import os

SHOWCASE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MONITOR_ROOT = Path("/mnt/e/os2026/ebpf-multi-agent-monitor")
MONITOR_ROOT = Path(os.environ.get("MONITOR_PROJECT_ROOT", DEFAULT_MONITOR_ROOT))
SQLITE_PATH = Path(
    os.environ.get(
        "MONITOR_SQLITE_PATH",
        MONITOR_ROOT / "logs" / "alerts" / "analysis.db",
    )
)
