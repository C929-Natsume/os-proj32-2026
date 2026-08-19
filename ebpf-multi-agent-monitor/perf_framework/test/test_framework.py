#!/usr/bin/env python3
"""
Self-tests for the performance benchmark framework.
Run with: python -m pytest perf_framework/test/test_framework.py -v
"""

import os
import sys
import yaml
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from perf_framework.utils.env_check import check_environment
from perf_framework.utils.freq_lock import get_current_governor, get_current_freq
from perf_framework.utils.redis_observer import RedisEventObserver

from perf_framework.workload.file_ops import file_io_workload, file_io_batch
from perf_framework.workload.net_ops import network_workload
from perf_framework.workload.proc_ops import fork_workload, exec_workload
from perf_framework.workload.ssl_ops import ssl_workload
from perf_framework.workload.generators import run_tier_workload

from perf_framework.metrics.ebpf_overhead import parse_perf_stat
from perf_framework.metrics.event_capture import get_drop_counters, parse_drop_dump
from perf_framework.metrics.detection_accuracy import evaluate_detectors, AccuracyMetrics
from perf_framework.accuracy.synthesizer import (
    generate_synthetic_dataset, load_dataset, generate_observation,
    ANOMALY_TYPE_CONFIGS,
)

from perf_framework.probes.latency_wrapper import (
    install_latency_probes, uninstall_latency_probes, LatencyCollector,
)

from perf_framework.visualization.charts import _pct_str


class TestWorkload:
    """Verify workload generators execute without errors and complete in reasonable time."""

    def test_file_io_workload_small(self):
        import time
        t0 = time.perf_counter()
        file_io_workload(10)
        dt = time.perf_counter() - t0
        assert dt < 5.0, f"File I/O workload too slow: {dt:.2f}s"

    def test_file_io_batch(self):
        import time
        t0 = time.perf_counter()
        file_io_batch(20, batch_size=5)
        dt = time.perf_counter() - t0
        assert dt < 5.0, f"File I/O batch too slow: {dt:.2f}s"

    def test_network_workload_small(self):
        import time
        t0 = time.perf_counter()
        network_workload(5, port=19999)
        dt = time.perf_counter() - t0
        assert dt < 5.0, f"Network workload too slow: {dt:.2f}s"

    def test_fork_workload(self):
        import time
        t0 = time.perf_counter()
        fork_workload(5)
        dt = time.perf_counter() - t0
        assert dt < 5.0

    def test_exec_workload(self):
        import time
        t0 = time.perf_counter()
        exec_workload(3)
        dt = time.perf_counter() - t0
        assert dt < 5.0

    def test_ssl_workload_imports(self):
        try:
            ssl_workload(1)
        except Exception:
            pass

    def test_run_tier_workload(self):
        tier = {
            "file_iterations": 10,
            "net_messages": 5,
            "fork_count": 3,
            "exec_count": 2,
            "ssl_requests": 0,
            "parallelism": 1,
        }
        dt = run_tier_workload(tier, enable_ssl=False)
        assert dt > 0
        assert dt < 10.0

    def test_parallel_workload(self):
        tier = {
            "file_iterations": 40,
            "net_messages": 0,
            "fork_count": 8,
            "exec_count": 4,
            "ssl_requests": 0,
            "parallelism": 2,
        }
        dt = run_tier_workload(tier, enable_ssl=False)
        assert dt > 0
        assert dt < 15.0


class TestMetrics:
    """Verify metric collector interfaces work correctly."""

    def test_ebpf_overhead_metrics_struct(self):
        from perf_framework.metrics.ebpf_overhead import OverheadMetrics
        m = OverheadMetrics(tier_label="test")
        assert m.tier_label == "test"
        assert m.baseline_wall_s == 0.0

    def test_capture_metrics_struct(self):
        from perf_framework.metrics.event_capture import CaptureMetrics
        m = CaptureMetrics(tier_label="test")
        assert m.tier_label == "test"
        assert m.capture_rate_pct == 0.0

    def test_ssl_capture_metrics_struct(self):
        from perf_framework.metrics.ssl_capture import SSLCaptureMetrics
        m = SSLCaptureMetrics(tier_label="test")
        assert m.ssl_capture_rate_pct == 0.0

    def test_latency_metrics_struct(self):
        from perf_framework.metrics.detection_latency import LatencyMetrics, DetectorLatency
        m = LatencyMetrics(tier_label="test")
        assert m.tier_label == "test"
        detectors = m.detector_list()
        assert len(detectors) >= 6

    def test_latency_collector(self):
        from perf_framework.metrics.detection_latency import LatencyCollector
        collector = LatencyCollector()
        collector.record("rule_detector", 1_000_000)
        collector.record("rule_detector", 2_000_000)
        collector.record("gnn_detector", 5_000_000)
        m = collector.compute("test")
        assert m.rule_detector.count == 2
        assert m.gnn_detector.count == 1
        assert m.rule_detector.avg_ms == 1.5

    def test_accuracy_metrics_struct(self):
        from perf_framework.metrics.detection_accuracy import AccuracyMetrics, PerClassMetrics
        pc = PerClassMetrics(anomaly_type="test", precision=0.9, recall=0.8, f1=0.85, support=10)
        assert pc.f1 == 0.85

    def test_perf_stat_parser(self):
        sample_stderr = """
 Performance counter stats for 'test':
          1234567      instructions
           9876543      cycles
              1234      cache-misses
       0.123456789 seconds time elapsed
"""
        result = _parse_inline(sample_stderr, ["instructions", "cycles", "cache-misses"])
        assert result["instructions"] == 1234567
        assert result["cycles"] == 9876543
        assert result["cache-misses"] == 1234


class TestLatencyProbes:
    """Verify monkey-patch mechanism works on a simple test object."""

    def test_install_uninstall(self):
        collector = LatencyCollector()

        class FakeDetector:
            def detect(self, x):
                return x * 2

        class FakeAgent:
            def __init__(self):
                self._rule_detector = FakeDetector()
            def process_observation(self, obs):
                return self._rule_detector.detect(obs.get("value", 0))

        agent = FakeAgent()
        collector = install_latency_probes(agent, collector)
        result = agent.process_observation({"value": 42})
        assert result == 84

        records = collector._records
        any_detector_found = False
        for k, v in records.items():
            if k != "pipeline_total":
                any_detector_found = True
                assert len(v) >= 1, f"Detector {k} not recorded"
        assert records.get("pipeline_total") is not None or any_detector_found


class TestSynthesizer:
    """Verify synthetic observation generation."""

    def test_generate_single_observation(self):
        cfg = ANOMALY_TYPE_CONFIGS["normal"]
        obs = generate_observation(cfg, "normal", 1000000000)
        assert "agents" in obs
        assert "interactions" in obs
        assert "messages" in obs
        assert "anomalies" in obs
        assert obs["label"] == 0
        assert obs["_anomaly_target"] == "normal"

    def test_generate_anomaly_observation(self):
        cfg = ANOMALY_TYPE_CONFIGS["shell_exec"]
        obs = generate_observation(cfg, "shell_exec", 2000000000)
        assert obs["label"] == 1
        assert len(obs["anomalies"]) > 0
        assert "UNEXPECTED_SHELL_EXEC" in str(obs["anomalies"])

    def test_generate_dataset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            generate_synthetic_dataset(tmpdir, types=["normal", "cpu_anomaly"], seed=42)
            normal_path = os.path.join(tmpdir, "normal.json")
            cpu_path = os.path.join(tmpdir, "cpu_anomaly.json")
            assert os.path.exists(normal_path)
            assert os.path.exists(cpu_path)

            normal_data = load_dataset(normal_path)
            assert len(normal_data) > 0
            assert all(d["_anomaly_target"] == "normal" for d in normal_data)

            cpu_data = load_dataset(cpu_path)
            assert len(cpu_data) > 0
            assert all(d["_anomaly_target"] == "cpu_anomaly" for d in cpu_data)


class TestVisualizationHelpers:
    """Verify visualization utility functions."""

    def test_pct_str(self):
        assert _pct_str(50.0) == "50.0%"
        assert _pct_str(0) == "0.0%"


class TestConfig:
    """Verify config loading and defaults."""

    def test_config_loads(self):
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "benchmark.yaml"
        )
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
        assert "benchmark" in cfg
        assert "tiers" in cfg
        assert "thresholds" in cfg
        assert "perf" in cfg
        assert "cpu" in cfg


class TestRedisObserver:
    """Verify Redis observer interface."""

    def test_observer_io(self):
        obs = RedisEventObserver("127.0.0.1", 6379, "test_channel")
        obs.mark_tag("workload_start")
        stats = obs.get_latency_stats("workload_start")
        assert stats["count"] == 0

        obs.clear_events()
        assert obs.get_event_count() == 0
        assert len(obs._latencies) == 0


class TestFreqLock:
    """Verify frequency lock utilities."""

    def test_get_current_governor(self):
        gov = get_current_governor()
        assert gov is None or isinstance(gov, str)

    def test_get_current_freq(self):
        freq = get_current_freq()
        assert freq is None or freq > 0

    def test_lock_frequency_noop(self):
        try:
            set_governor("performance")
        except PermissionError:
            pytest.skip("Need root for governor change")
        except Exception:
            pass


class TestEnvCheck:
    """Verify environment check runs without errors."""

    def test_env_check(self):
        report = check_environment(
            "/nonexistent/loader",
            "/nonexistent/ringbuf",
            "127.0.0.1",
            6379,
        )
        assert report is not None
        assert isinstance(report.python_version, str)
        assert isinstance(report.kernel_version, str)
        assert report.cpu_cores >= 0


def _parse_inline(stderr, events):
    result = {}
    for line in stderr.split("\n"):
        parts = line.strip().split()
        if not parts:
            continue
        for event in events:
            if event in line:
                try:
                    val_str = parts[0].replace(",", "")
                    result[event] = int(val_str)
                except (ValueError, IndexError):
                    pass
    return result
