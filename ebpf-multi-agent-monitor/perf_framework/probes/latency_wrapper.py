import time
import functools
from typing import Dict, Optional


class LatencyCollector:
    """Injected at runtime to collect per-detector latencies."""

    def __init__(self):
        self._records: Dict[str, list] = {}

    def record(self, name: str, duration_ns: int):
        if name not in self._records:
            self._records[name] = []
        self._records[name].append(duration_ns)

    def clear(self):
        self._records.clear()

    def snapshot(self) -> Dict:
        return dict(self._records)


_global_collector: Optional[LatencyCollector] = None


def install_latency_probes(monitor_agent, collector: Optional[LatencyCollector] = None):
    """Monkey-patch MonitorAgent.process_observation to collect per-detector latency."""
    global _global_collector

    if collector is not None:
        _global_collector = collector
    elif _global_collector is None:
        _global_collector = LatencyCollector()

    c = _global_collector
    original_process = monitor_agent.process_observation

    @functools.wraps(original_process)
    def timed_process_observation(obs: dict):
        t_total = time.perf_counter_ns()

        # Wrap each detector's detect/call method
        _wrap_method_if_exists(monitor_agent, "_rule_detector", "detect", c, "rule_detector")
        _wrap_method_if_exists(monitor_agent, "_gnn_detector", "detect", c, "gnn_detector")
        _wrap_method_if_exists(monitor_agent, "_temporal_detector", "detect", c, "temporal_detector")
        _wrap_method_if_exists(monitor_agent, "_semantic_rule_checker", "check", c, "semantic_checker")
        _wrap_method_if_exists(monitor_agent, "_message_detector", "detect", c, "message_detector")
        _wrap_method_if_exists(monitor_agent, "_propagation_analyzer", "analyze", c, "propagation_analyzer")

        result = original_process(obs)

        dt_total = time.perf_counter_ns() - t_total
        c.record("pipeline_total", dt_total)
        return result

    monitor_agent.process_observation = timed_process_observation
    return _global_collector


def uninstall_latency_probes(monitor_agent):
    """Restore original process_observation method."""
    if hasattr(monitor_agent, "_original_process_observation"):
        monitor_agent.process_observation = monitor_agent._original_process_observation


def _wrap_method_if_exists(obj, attr_name, method_name, collector, label):
    """Wrap obj.attr_name.method_name to measure latency."""
    detector = getattr(obj, attr_name, None)
    if detector is None:
        return
    method = getattr(detector, method_name, None)
    if method is None:
        return

    _cache_key = f"_perf_original_{attr_name}_{method_name}"
    if hasattr(detector, _cache_key):
        return

    original = method
    setattr(detector, _cache_key, original)

    @functools.wraps(original)
    def wrapped(*args, **kwargs):
        t0 = time.perf_counter_ns()
        result = original(*args, **kwargs)
        collector.record(label, time.perf_counter_ns() - t0)
        return result

    setattr(detector, method_name, wrapped)
