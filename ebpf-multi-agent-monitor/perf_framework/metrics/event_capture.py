import subprocess
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CaptureMetrics:
    tier_label: str = ""
    total_sys_events: int = 0
    total_raw_events: int = 0
    total_ssl_events: int = 0
    drop_sys: int = 0
    drop_connect: int = 0
    drop_fork: int = 0
    drop_raw: int = 0
    drop_msghdr: int = 0
    total_drops: int = 0
    capture_rate_pct: Optional[float] = None
    has_data: bool = False
    sys_events_per_sec: float = 0.0
    raw_events_per_sec: float = 0.0
    ssl_events_per_sec: float = 0.0
    elapsed_seconds: float = 0.0


DROP_REASONS = {
    "sys": "DROP_SYS_EVENT",
    "connect": "DROP_CONNECT_EVENT",
    "fork": "DROP_FORK_EVENT",
    "raw": "DROP_RAW_EVENT",
    "msghdr": "DROP_MSGHDR_EVENT",
}


def get_drop_counters() -> Dict[str, int]:
    """Read drop_counters BPF map via bpftool."""
    result = {"sys": 0, "connect": 0, "fork": 0, "raw": 0, "msghdr": 0}
    try:
        out = subprocess.check_output(
            ["bpftool", "map", "list"], text=True, timeout=5
        )
    except Exception:
        return result

    drop_id = None
    for line in out.split("\n"):
        if "drop_counters" in line:
            parts = line.strip().split(":")
            if parts:
                drop_id = parts[0].strip()
                break

    if not drop_id:
        return result

    try:
        dump = subprocess.check_output(
            ["bpftool", "map", "dump", "id", drop_id],
            text=True, timeout=5
        )
    except Exception:
        return result

    idx = 0
    for line in dump.split("\n"):
        match = None
        for m in ("sys", "connect", "fork", "raw", "msghdr"):
            if m in line.lower():
                match = m
                break
        if match:
            try:
                val_part = line.split("value:")[-1].strip().split()[0]
                result[match] += int(val_part, 16)
            except Exception:
                pass
        idx += 1
        if idx >= 5:
            break

    return result


def get_ssl_drop_counter() -> int:
    try:
        out = subprocess.check_output(
            ["bpftool", "map", "list"], text=True, timeout=5
        )
    except Exception:
        return 0

    drop_id = None
    for line in out.split("\n"):
        if "ssl_drop_counter" in line:
            parts = line.strip().split(":")
            if parts:
                drop_id = parts[0].strip()
                break

    if not drop_id:
        return 0

    try:
        dump = subprocess.check_output(
            ["bpftool", "map", "dump", "id", drop_id],
            text=True, timeout=5
        )
    except Exception:
        return 0

    total = 0
    for line in dump.split("\n"):
        try:
            if "value:" in line:
                val_part = line.split("value:")[-1].strip().split()[0]
                total += int(val_part, 16)
        except Exception:
            pass
    return total


def get_redis_event_counts(redis_host: str, redis_port: int) -> Tuple[int, int]:
    """Get event counts from Redis streams. Returns (sys_events, ssl_events)."""
    import redis as redispy
    sys_count = 0
    ssl_count = 0
    try:
        client = redispy.Redis(host=redis_host, port=redis_port, socket_timeout=3)
        sys_count = client.xlen("inter:events") or 0
        ssl_count = client.xlen("inter:messages") or 0
        client.close()
    except Exception:
        pass
    return sys_count, ssl_count


def measure_event_capture(
    tier_label: str,
    elapsed_seconds: float,
    ringbuf_log: str,
    redis_host: str,
    redis_port: int,
    drops: Optional[Dict[str, int]] = None,
) -> CaptureMetrics:
    """Measure event capture from the ringbuf log (mirrors test_perf.sh).

    sys_events  = grep -c '-> Type:' ringbuf_log
    raw_events  = grep -cE '(FD:|Source:)' ringbuf_log
    drops       = bpftool map dump drop_counters
    capture_rate = (sys+raw) / (sys+raw+drops) * 100
    """
    m = CaptureMetrics(tier_label=tier_label, elapsed_seconds=elapsed_seconds)

    if drops is None:
        drops = get_drop_counters()
    m.drop_sys = drops.get("sys", 0)
    m.drop_connect = drops.get("connect", 0)
    m.drop_fork = drops.get("fork", 0)
    m.drop_raw = drops.get("raw", 0)
    m.drop_msghdr = drops.get("msghdr", 0)
    m.total_drops = sum(drops.values())

    sys_events = count_sys_events(ringbuf_log)
    raw_events = count_raw_events(ringbuf_log)
    ssl_events = count_ssl_events(ringbuf_log)
    m.total_sys_events = sys_events
    m.total_raw_events = raw_events
    m.total_ssl_events = ssl_events

    total_with_drops = sys_events + raw_events + m.total_drops
    if total_with_drops > 0:
        m.capture_rate_pct = (sys_events + raw_events) / total_with_drops * 100
        m.has_data = True
    else:
        m.capture_rate_pct = None
        m.has_data = False

    if elapsed_seconds > 0:
        m.sys_events_per_sec = sys_events / elapsed_seconds
        m.raw_events_per_sec = raw_events / elapsed_seconds
        m.ssl_events_per_sec = ssl_events / elapsed_seconds

    return m


def count_sys_events(ringbuf_log: str) -> int:
    """Count sys events: grep -c '\-> Type:' (mirrors test_perf.sh)."""
    try:
        with open(ringbuf_log, "r", errors="replace") as f:
            return sum(1 for line in f if "-> Type:" in line)
    except Exception:
        return 0


def count_raw_events(ringbuf_log: str) -> int:
    """Count raw events: grep -cE '(FD:|Source:)' (mirrors test_perf.sh)."""
    try:
        with open(ringbuf_log, "r", errors="replace") as f:
            return sum(1 for line in f if "FD:" in line or "Source:" in line)
    except Exception:
        return 0


def count_ssl_events(ringbuf_log: str) -> int:
    """Count SSL events: SSL EVENT INTERCEPTED markers."""
    try:
        with open(ringbuf_log, "r", errors="replace") as f:
            return sum(1 for line in f if "SSL EVENT INTERCEPTED" in line)
    except Exception:
        return 0
