import os
import time
import subprocess
from typing import Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field


@dataclass
class OverheadMetrics:
    tier_label: str = ""
    baseline_wall_s: float = 0.0
    fastpath_wall_s: float = 0.0
    fullcapture_wall_s: float = 0.0
    baseline_instr: int = 0
    fastpath_instr: int = 0
    fullcapture_instr: int = 0
    baseline_cycles: int = 0
    fastpath_cycles: int = 0
    fullcapture_cycles: int = 0
    baseline_cache_misses: int = 0
    fastpath_cache_misses: int = 0
    fullcapture_cache_misses: int = 0
    baseline_branches: int = 0
    fastpath_branches: int = 0
    fullcapture_branches: int = 0
    fastpath_overhead_pct: float = 0.0
    fullcapture_overhead_pct: float = 0.0
    baseline_has_perf: bool = False
    fastpath_has_perf: bool = False
    fullcapture_has_perf: bool = False
    perf_metric: str = "instructions"


def _parse_perf_stat(stderr: str, events: List[str]) -> Dict[str, int]:
    metrics: Dict[str, int] = {e: 0 for e in events}
    for line in stderr.split("\n"):
        parts = line.strip().split()
        if not parts:
            continue
        for event in events:
            if event in line:
                try:
                    val_str = parts[0].replace(",", "")
                    metrics[event] = int(val_str)
                except (ValueError, IndexError):
                    pass
    return metrics


def _parse_perf_stat_file(path: str, events: List[str]) -> Dict[str, int]:
    try:
        with open(path, "r") as f:
            return _parse_perf_stat(f.read(), events)
    except Exception:
        return {e: 0 for e in events}


def _median(vals: List[float]) -> float:
    if not vals:
        return 0.0
    sorted_vals = sorted(vals)
    return sorted_vals[len(sorted_vals) // 2]


def measure_ebpf_overhead(tier_label: str,
                          phase_fn: Callable,
                          perf_events: List[str],
                          iterations: int = 3,
                          metric: str = "instructions") -> OverheadMetrics:
    """Run 3 phases (baseline/fastpath/fullcapture) via a phase_fn callback.

    phase_fn(phase, perf_events) -> (wall_s, {event: count})
    Each phase runs `iterations` times and uses the median.
    """
    m = OverheadMetrics(tier_label=tier_label)
    m.perf_metric = metric

    for phase, attr in (
        ("baseline", "baseline"),
        ("fastpath", "fastpath"),
        ("fullcapture", "fullcapture"),
    ):
        walls = []
        perfs = {e: [] for e in perf_events}
        for _ in range(iterations):
            wall, counts = phase_fn(phase, perf_events)
            walls.append(wall)
            for e in perf_events:
                perfs[e].append(counts.get(e, 0))

        m_wall = _median(walls)
        m_perf = {e: _median([float(v) for v in perfs[e]]) for e in perf_events}

        setattr(m, f"{phase}_wall_s", m_wall)
        setattr(m, f"{phase}_instr", int(m_perf.get("instructions", 0)))
        setattr(m, f"{phase}_cycles", int(m_perf.get("cycles", 0)))
        setattr(m, f"{phase}_cache_misses", int(m_perf.get("cache-misses", 0)))
        setattr(m, f"{phase}_branches", int(m_perf.get("branches", 0)))
        setattr(m, f"{phase}_has_perf", _any_nonzero(m_perf))

    # Overhead % based on instruction counts
    if m.baseline_instr > 0 and m.fastpath_instr > 0:
        m.fastpath_overhead_pct = (
            (m.fastpath_instr - m.baseline_instr) / m.baseline_instr * 100
        )
    if m.baseline_instr > 0 and m.fullcapture_instr > 0:
        m.fullcapture_overhead_pct = (
            (m.fullcapture_instr - m.baseline_instr) / m.baseline_instr * 100
        )

    # Fallback: wall-clock based overhead if perf unavailable
    if not m.baseline_has_perf:
        if m.baseline_wall_s > 0 and m.fastpath_wall_s > 0:
            m.fastpath_overhead_pct = (
                (m.fastpath_wall_s - m.baseline_wall_s) / m.baseline_wall_s * 100
            )
        if m.baseline_wall_s > 0 and m.fullcapture_wall_s > 0:
            m.fullcapture_overhead_pct = (
                (m.fullcapture_wall_s - m.baseline_wall_s) / m.baseline_wall_s * 100
            )
        m.perf_metric = "wall-clock"

    return m


def _any_nonzero(counts: Dict[str, int]) -> bool:
    return any(v > 0 for v in counts.values())
