import time
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class SSLCaptureMetrics:
    tier_label: str = ""
    ssl_events_captured: int = 0
    ssl_events_expected: int = 0
    ssl_drops: int = 0
    ssl_capture_rate_pct: float = 0.0
    chunk_total: int = 0
    chunk_orphaned: int = 0
    chunk_reassembly_rate_pct: float = 0.0
    ssl_bytes_total: int = 0
    ssl_throughput_bytes_per_sec: float = 0.0
    avg_ssl_delta_ns: int = 0
    elapsed_seconds: float = 0.0


def measure_ssl_capture(
    tier_label: str,
    expected_ssl_requests: int,
    elapsed_seconds: float,
    redis_host: str,
    redis_port: int,
) -> SSLCaptureMetrics:
    m = SSLCaptureMetrics(
        tier_label=tier_label,
        ssl_events_expected=expected_ssl_requests,
        elapsed_seconds=elapsed_seconds,
    )

    m.ssl_drops = _get_ssl_drops()

    try:
        import redis as redispy
        client = redispy.Redis(host=redis_host, port=redis_port, socket_timeout=3)

        m.ssl_events_captured = client.xlen("inter:messages") or 0

        edge_keys = client.smembers("inter:edges") or []
        for ek in edge_keys:
            key = ek.decode() if isinstance(ek, bytes) else ek
            hdata = client.hgetall(f"inter:edge:{key}")
            if hdata:
                try:
                    ssl_total = int(hdata.get(b"ssl_total_bytes",
                                              hdata.get("ssl_total_bytes", 0)))
                    m.ssl_bytes_total += ssl_total
                except Exception:
                    pass

        client.close()
    except Exception:
        pass

    if expected_ssl_requests > 0:
        m.ssl_capture_rate_pct = (
            min(m.ssl_events_captured, expected_ssl_requests) / expected_ssl_requests * 100
        )

    if elapsed_seconds > 0:
        m.ssl_throughput_bytes_per_sec = m.ssl_bytes_total / elapsed_seconds

    m.chunk_total = _count_chunk_streams(redis_host, redis_port)
    m.chunk_orphaned = _count_orphaned_chunks(redis_host, redis_port)
    if m.chunk_total > 0:
        m.chunk_reassembly_rate_pct = (
            (m.chunk_total - m.chunk_orphaned) / m.chunk_total * 100
        )
    else:
        m.chunk_reassembly_rate_pct = 100.0

    return m


def _get_ssl_drops() -> int:
    try:
        out = subprocess.check_output(
            ["bpftool", "map", "list"], text=True, timeout=5
        )
    except Exception:
        return 0
    drop_id = None
    for line in out.split("\n"):
        if "ssl_drop_counter" in line:
            drop_id = line.strip().split(":")[0].strip()
            break
    if not drop_id:
        return 0
    try:
        dump = subprocess.check_output(
            ["bpftool", "map", "dump", "id", drop_id], text=True, timeout=5
        )
    except Exception:
        return 0
    total = 0
    for line in dump.split("\n"):
        try:
            if "value:" in line:
                total += int(line.split("value:")[-1].strip().split()[0], 16)
        except Exception:
            pass
    return total


def _count_chunk_streams(redis_host: str, redis_port: int) -> int:
    try:
        import redis as redispy
        client = redispy.Redis(host=redis_host, port=redis_port, socket_timeout=3)
        keys = client.keys("ssl:chunk:*")
        client.close()
        return len(keys)
    except Exception:
        return 0


def _count_orphaned_chunks(redis_host: str, redis_port: int) -> int:
    try:
        import redis as redispy
        client = redispy.Redis(host=redis_host, port=redis_port, socket_timeout=3)
        keys = client.keys("ssl:chunk:*")
        orphaned = 0
        now = time.time()
        for k in keys:
            ttl = client.ttl(k)
            if ttl and ttl < 0:
                orphaned += 1
        client.close()
        return orphaned
    except Exception:
        return 0
