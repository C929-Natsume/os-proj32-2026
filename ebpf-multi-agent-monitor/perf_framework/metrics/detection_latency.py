import time
import json
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class DetectorLatency:
    name: str
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    avg_ms: float = 0.0
    count: int = 0

@dataclass
class LatencyMetrics:
    tier_label: str = ""
    pipeline_total: DetectorLatency = field(default_factory=lambda: DetectorLatency("pipeline_total"))
    rule_detector: DetectorLatency = field(default_factory=lambda: DetectorLatency("rule_detector"))
    gnn_detector: DetectorLatency = field(default_factory=lambda: DetectorLatency("gnn_detector"))
    temporal_detector: DetectorLatency = field(default_factory=lambda: DetectorLatency("temporal_detector"))
    semantic_checker: DetectorLatency = field(default_factory=lambda: DetectorLatency("semantic_checker"))
    message_detector: DetectorLatency = field(default_factory=lambda: DetectorLatency("message_detector"))
    propagation_analyzer: DetectorLatency = field(default_factory=lambda: DetectorLatency("propagation_analyzer"))
    c_layer_latency_us: float = 0.0

    def detector_list(self):
        return [
            self.pipeline_total, self.rule_detector, self.gnn_detector,
            self.temporal_detector, self.semantic_checker,
            self.message_detector, self.propagation_analyzer,
        ]


class LatencyCollector:
    """Collect per-detector latency via monkey-patch at runtime."""

    def __init__(self):
        self._records: Dict[str, List[float]] = defaultdict(list)

    def record(self, name: str, duration_ns: int):
        self._records[name].append(duration_ns)

    def clear(self):
        self._records.clear()

    def compute(self, tier_label: str) -> LatencyMetrics:
        m = LatencyMetrics(tier_label=tier_label)
        for field_name in [
            "pipeline_total", "rule_detector", "gnn_detector",
            "temporal_detector", "semantic_checker",
            "message_detector", "propagation_analyzer",
        ]:
            vals = self._records.get(field_name, [])
            dl = DetectorLatency(name=field_name, count=len(vals))
            if vals:
                sorted_vals = sorted(vals)
                n = len(sorted_vals)
                dl.p50_ms = sorted_vals[n // 2] / 1_000_000
                dl.p95_ms = sorted_vals[int(n * 0.95)] / 1_000_000
                dl.p99_ms = sorted_vals[int(n * 0.99)] / 1_000_000
                dl.min_ms = sorted_vals[0] / 1_000_000
                dl.max_ms = sorted_vals[-1] / 1_000_000
                dl.avg_ms = sum(sorted_vals) / n / 1_000_000
            setattr(m, field_name, dl)
        return m


def measure_detection_latency(
    tier_label: str,
    collector: LatencyCollector,
    observer_stats: Dict,
    elapsed_seconds: float,
) -> LatencyMetrics:
    m = collector.compute(tier_label)

    all_c_ns = []
    for tag, vals in observer_stats.items():
        all_c_ns.extend(vals)
    if all_c_ns:
        m.c_layer_latency_us = sum(all_c_ns) / len(all_c_ns) / 1000

    return m
