#!/usr/bin/env python3
"""
eBPF Multi-Agent Monitor — Professional Performance Benchmark Runner

Orchestrates 4 workload tiers × 5 metric dimensions × N iterations,
generates a 7-page PDF report.

Usage:
    sudo python -m perf_framework.runner --full
    sudo python -m perf_framework.runner --smoke
    python -m perf_framework.runner --accuracy-only
"""

import os
import sys
import time
import yaml
import argparse
import subprocess
import signal
import random
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "analysis"))

from perf_framework.utils.env_check import check_environment, print_env_report
from perf_framework.utils.freq_lock import set_governor, lock_frequency, get_current_freq
from perf_framework.utils.redis_observer import RedisEventObserver
from perf_framework.utils.proc_name import rename_comm

from perf_framework.workload.generate_wrapper import (
    get_wrapper_script, run_wrapper_with_perf, run_wrapper_workload,
)

from perf_framework.metrics.ebpf_overhead import (
    measure_ebpf_overhead, OverheadMetrics,
)
from perf_framework.metrics.event_capture import (
    measure_event_capture, get_drop_counters, CaptureMetrics
)
from perf_framework.metrics.ssl_capture import (
    measure_ssl_capture, SSLCaptureMetrics
)
from perf_framework.metrics.detection_latency import (
    LatencyCollector, LatencyMetrics,
    measure_detection_latency,
)
from perf_framework.metrics.detection_accuracy import (
    evaluate_detectors, AccuracyMetrics, ANOMALY_TYPES
)
from perf_framework.accuracy.synthesizer import (
    generate_synthetic_dataset, load_dataset
)

from perf_framework.probes.latency_wrapper import (
    install_latency_probes, uninstall_latency_probes,
)

from perf_framework.visualization.report import generate_report, generate_csv


class BenchmarkRunner:
    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            self.cfg = yaml.safe_load(f)
        self._tier_labels: List[str] = []
        self._results: Dict = defaultdict(dict)
        self._raw_csv: Dict[str, list] = defaultdict(list)

    def run(self, tiers_filter: Optional[List[str]] = None,
            iterations: Optional[int] = None,
            skip_bpf: bool = False,
            skip_accuracy: bool = False,
            smoke: bool = False):

        # 1. Environment check
        cfg_bpf = self.cfg.get("bpf", {})
        loader_path = cfg_bpf.get("loader_binary", "../build/loader")
        ringbuf_path = cfg_bpf.get("ringbuf_handler_binary", "../build/ringbuf_handler")
        cfg_redis = self.cfg.get("redis", {})
        env = check_environment(loader_path, ringbuf_path,
                                 cfg_redis.get("host", "127.0.0.1"),
                                 cfg_redis.get("port", 6379))
        print_env_report(env)
        if env.errors:
            print("\n[WARN] Environment has issues — some tests may fail.\n")

        # 2. Select tiers
        all_tiers = self.cfg.get("tiers", {})
        if tiers_filter:
            tier_names = tiers_filter
        else:
            tier_names = list(all_tiers.keys())
        if smoke:
            tier_names = [tier_names[0]] if tier_names else []
            iterations = 1
        if iterations is None:
            iterations = self.cfg.get("benchmark", {}).get("iterations", 3)
        self._tier_labels = [all_tiers[t]["label"] for t in tier_names]

        print(f"\nTiers: {self._tier_labels}")
        print(f"Iterations per tier: {iterations}")
        print(f"Skip BPF tests: {skip_bpf}")
        print(f"Skip accuracy tests: {skip_accuracy}\n")

        # 3. CPU frequency lock
        try:
            cpu_cfg = self.cfg.get("cpu", {})
            if cpu_cfg.get("use_cpupower", True):
                set_governor(cpu_cfg.get("governor", "performance"))
                lock_frequency(cpu_cfg.get("lock_frequency_ghz", 2.0))
                freq = get_current_freq()
                print(f"CPU frequency locked to {freq:.2f} GHz\n")
        except Exception as e:
            print(f"[WARN] CPU freq lock failed: {e}\n")

        # 4. Accuracy tests (no BPF needed)
        if not skip_accuracy:
            self._run_accuracy_tests()

        # 5. BPF performance tests
        if not skip_bpf and not skip_bpf:
            self._run_bpf_benchmarks(tier_names, all_tiers, iterations)

        # 6. Generate reports
        self._generate_reports(env)

    def _run_accuracy_tests(self):
        print("=" * 60)
        print("  Accuracy Benchmark: Generating synthetic dataset & evaluating")
        print("=" * 60)

        cfg_out = self.cfg.get("output", {})
        dataset_dir = cfg_out.get("raw_data_dir", "./reports/raw_data") + "/datasets"
        dataset_dir = _ensure_writable(dataset_dir)
        try:
            generate_synthetic_dataset(dataset_dir, types=ANOMALY_TYPES[:8], seed=42)
        except Exception as e:
            print(f"[WARN] Dataset generation failed: {e}")

        all_obs_path = os.path.join(dataset_dir, "all_synthetic.json")
        if not os.path.exists(all_obs_path):
            print("[WARN] No synthetic data found — check requirements (sklearn, etc.)")
            return

        try:
            from inter_agent.monitor.agent import MonitorAgent
            from inter_agent.config.loader import load_config
        except ImportError as e:
            print(f"[WARN] Cannot import analysis modules: {e}")
            return

        observations = load_dataset(all_obs_path)
        sample_size = min(500, len(observations))
        observations = random.sample(observations, sample_size)
        print(f"  Evaluating on {sample_size} samples...")

        try:
            inter_config = load_config()
        except Exception:
            inter_config = {}

        def agent_factory():
            return MonitorAgent(config=inter_config)

        t0 = time.time()
        acc_result = evaluate_detectors(agent_factory, observations, ANOMALY_TYPES[:8])
        elapsed = time.time() - t0
        print(f"  Evaluation completed in {elapsed:.1f}s")
        print(f"  Accuracy: {acc_result.overall_accuracy:.3f}  "
              f"Macro F1: {acc_result.macro_f1:.3f}  "
              f"Weighted F1: {acc_result.weighted_f1:.3f}")

        self._results["accuracy"] = {
            "overall_accuracy": acc_result.overall_accuracy,
            "macro_precision": acc_result.macro_precision,
            "macro_recall": acc_result.macro_recall,
            "macro_f1": acc_result.macro_f1,
            "weighted_f1": acc_result.weighted_f1,
            "auc_roc": acc_result.auc_roc,
            "per_class": [{
                "anomaly_type": pc.anomaly_type,
                "precision": pc.precision,
                "recall": pc.recall,
                "f1": pc.f1,
                "support": pc.support,
                "tp": pc.tp, "fp": pc.fp, "fn": pc.fn, "tn": pc.tn,
            } for pc in acc_result.per_class],
            "confusion_matrix": acc_result.confusion_matrix,
            "class_names": acc_result.class_names,
            "total_samples": acc_result.total_samples,
        }

    def _run_bpf_benchmarks(self, tier_names, all_tiers, iterations):
        print("=" * 60)
        print("  BPF Performance Benchmarks")
        print("=" * 60)

        cfg_redis = self.cfg.get("redis", {})
        redis_host = cfg_redis.get("host", "127.0.0.1")
        redis_port = cfg_redis.get("port", 6379)
        observer = RedisEventObserver(redis_host, redis_port, cfg_redis.get("event_channel", "ebpf_events"))

        overhead_tiers: Dict[str, Dict] = {}
        capture_tiers: Dict[str, Dict] = {}
        ssl_tiers: Dict[str, Dict] = {}
        latency_tiers: Dict[str, Dict] = {}

        for tname in tier_names:
            tier_cfg = all_tiers[tname]
            label = tier_cfg["label"]
            print(f"\n--- Tier: {label} ({iterations} iterations) ---")

            oh_metrics_list: List[Dict] = []
            cap_metrics_list: List[Dict] = []
            ssl_metrics_list: List[Dict] = []
            lat_metrics_list: List[Dict] = []

            for it in range(iterations):
                print(f"  Iteration {it + 1}/{iterations}...")
                self._flush_redis(redis_host, redis_port)

                observer.start()
                observer.clear_events()
                time.sleep(0.2)

                latency_collector = LatencyCollector()
                try:
                    from inter_agent.monitor.agent import MonitorAgent
                    from inter_agent.config.loader import load_config
                    inter_config = load_config()
                    agent = MonitorAgent(config=inter_config)
                    install_latency_probes(agent, latency_collector)
                    has_agent = True
                except Exception:
                    has_agent = False
                    agent = None

                wrapper_path = get_wrapper_script()
                perf_events = self.cfg.get("perf", {}).get("events", ["instructions"])

                # Workload selection: burst uses the burst fn; others use scaled workload.
                # Tier params are passed via env so the bash wrapper mirrors the config.
                wl_env = {
                    "FILE_IO_N": str(tier_cfg.get("file_iterations", 200)),
                    "NET_N": str(tier_cfg.get("net_messages", 50)),
                    "FORK_N": str(tier_cfg.get("fork_count", 30)),
                    "NET_PORT": "19999",
                }
                if tname == "burst":
                    wl_fn = "workload_burst"
                    wl_args = [str(tier_cfg.get("parallelism", 8))]
                else:
                    wl_fn = "workload"
                    wl_args = ["1"]

                def bpf_measure_fn(phase, events):
                    return self._phases_with_bpf(
                        wrapper_path, wl_fn, wl_args, events, phase, tier_cfg,
                        env=wl_env,
                    )

                # NOTE: measure_ebpf_overhead runs each phase once (outer loop
                # provides the N iterations; median is computed at tier level).
                oh = measure_ebpf_overhead(
                    label, bpf_measure_fn, perf_events,
                    iterations=1, metric="instructions",
                )
                oh_dict = {
                    "baseline_wall_s": oh.baseline_wall_s,
                    "fastpath_wall_s": oh.fastpath_wall_s,
                    "fullcapture_wall_s": oh.fullcapture_wall_s,
                    "baseline_instr": oh.baseline_instr,
                    "fastpath_instr": oh.fastpath_instr,
                    "fullcapture_instr": oh.fullcapture_instr,
                    "baseline_cycles": oh.baseline_cycles,
                    "fastpath_cycles": oh.fastpath_cycles,
                    "fullcapture_cycles": oh.fullcapture_cycles,
                    "baseline_cache_misses": oh.baseline_cache_misses,
                    "fastpath_cache_misses": oh.fastpath_cache_misses,
                    "fullcapture_cache_misses": oh.fullcapture_cache_misses,
                    "baseline_branches": oh.baseline_branches,
                    "fastpath_branches": oh.fastpath_branches,
                    "fullcapture_branches": oh.fullcapture_branches,
                    "fastpath_overhead_pct": oh.fastpath_overhead_pct,
                    "fullcapture_overhead_pct": oh.fullcapture_overhead_pct,
                }
                oh_metrics_list.append(oh_dict)
                self._raw_csv["ebpf_overhead"].append({"tier": label, "iteration": it, **oh_dict})

                # Feed captured Redis data into the analysis pipeline to
                # measure real detector latency (BPF fullcapture already flushed)
                if has_agent and agent:
                    try:
                        from inter_agent.data.collector import RedisCollector
                        collector = RedisCollector(
                            host=redis_host, port=redis_port,
                            window_seconds=self.cfg.get("redis", {}).get("window_seconds", 30),
                        )
                        obs_data = collector.get_observation()
                        agent.process_observation(obs_data)
                    except Exception:
                        pass

                # Capture metrics from ringbuf log + drop counters
                ringbuf_log = self.cfg.get("bpf", {}).get("ringbuf_log", "/tmp/perf_bench_ringbuf.log")
                cap = measure_event_capture(
                    label, oh.fullcapture_wall_s or oh.baseline_wall_s,
                    ringbuf_log, redis_host, redis_port
                )
                cap_dict = {
                    "total_sys_events": cap.total_sys_events,
                    "total_raw_events": cap.total_raw_events,
                    "total_ssl_events": cap.total_ssl_events,
                    "drop_sys": cap.drop_sys,
                    "drop_connect": cap.drop_connect,
                    "drop_fork": cap.drop_fork,
                    "drop_raw": cap.drop_raw,
                    "drop_msghdr": cap.drop_msghdr,
                    "total_drops": cap.total_drops,
                    "capture_rate_pct": cap.capture_rate_pct,
                    "sys_events_per_sec": cap.sys_events_per_sec,
                    "raw_events_per_sec": cap.raw_events_per_sec,
                    "ssl_events_per_sec": cap.ssl_events_per_sec,
                }
                cap_metrics_list.append(cap_dict)
                self._raw_csv["event_capture"].append({"tier": label, "iteration": it, **cap_dict})

                # SSL metrics
                ssl = measure_ssl_capture(
                    label, tier_cfg.get("ssl_requests", 10),
                    oh.fullcapture_wall_s or oh.baseline_wall_s,
                    redis_host, redis_port
                )
                ssl_dict = {
                    "ssl_events_captured": ssl.ssl_events_captured,
                    "ssl_events_expected": ssl.ssl_events_expected,
                    "ssl_drops": ssl.ssl_drops,
                    "ssl_capture_rate_pct": ssl.ssl_capture_rate_pct,
                    "chunk_total": ssl.chunk_total,
                    "chunk_orphaned": ssl.chunk_orphaned,
                    "chunk_reassembly_rate_pct": ssl.chunk_reassembly_rate_pct,
                    "ssl_bytes_total": ssl.ssl_bytes_total,
                    "ssl_throughput_bytes_per_sec": ssl.ssl_throughput_bytes_per_sec,
                }
                ssl_metrics_list.append(ssl_dict)
                self._raw_csv["ssl_capture"].append({"tier": label, "iteration": it, **ssl_dict})

                # Latency metrics
                observer_stats = observer.stop() if observer else {}
                lat = measure_detection_latency(
                    label, latency_collector, observer_stats,
                    oh.fullcapture_wall_s or oh.baseline_wall_s
                )
                lat_dict = {}
                for dl in lat.detector_list():
                    lat_dict[dl.name] = {
                        "p50_ms": dl.p50_ms, "p95_ms": dl.p95_ms,
                        "p99_ms": dl.p99_ms, "min_ms": dl.min_ms,
                        "max_ms": dl.max_ms, "avg_ms": dl.avg_ms, "count": dl.count,
                    }
                lat_dict["c_layer_latency_us"] = lat.c_layer_latency_us
                lat_metrics_list.append(lat_dict)
                self._raw_csv["detection_latency"].append({"tier": label, "iteration": it, **lat_dict})

                if has_agent and agent:
                    try:
                        uninstall_latency_probes(agent)
                    except Exception:
                        pass

                self._stop_bpf()
                time.sleep(self.cfg.get("benchmark", {}).get("cooldown_seconds", 5))

            overhead_tiers[label] = _median_overhead(oh_metrics_list)
            capture_tiers[label] = _median_capture(cap_metrics_list)
            ssl_tiers[label] = _median_ssl(ssl_metrics_list)
            latency_tiers[label] = _median_latency(lat_metrics_list)

            cap_avg = capture_tiers[label].get('capture_rate_pct')
            cap_str = f"{cap_avg:.1f}%" if cap_avg is not None else "NO-DATA"
            print(f"  {label} avg: fastpath_oh={overhead_tiers[label].get('fastpath_overhead_pct',0):.1f}%  "
                  f"fullcapture_oh={overhead_tiers[label].get('fullcapture_overhead_pct',0):.1f}%  "
                  f"capture={cap_str}")

        self._results["overhead"] = {"tiers": overhead_tiers}
        self._results["capture"] = {"tiers": capture_tiers}
        self._results["ssl"] = {"tiers": ssl_tiers}
        self._results["latency"] = {"tiers": latency_tiers}

    def _phases_with_bpf(self, wrapper_path, wl_fn, wl_args, perf_events, phase, tier_cfg,
                         env=None):
        """Run a workload phase with BPF loaded. Returns (wall_s, perf_counts).

        Mirrors test_perf.sh phase flow:
        - baseline    : no BPF loaded; workload runs in bash subprocess under perf stat
        - fastpath    : loader started WITHOUT PID (probes attached, not monitored)
        - fullcapture : loader started WITH this PID (probes attached + monitored)
        """
        if phase == "fullcapture":
            register_pid = os.getpid()
            rename_comm("bench_runner")
            print(f"  [INFO] Full-capture: registering PID {register_pid} with loader...")
        elif phase == "fastpath":
            register_pid = None
            print("  [INFO] Fast-path: BPF loaded, PID not registered")
        else:
            register_pid = None
            print("  [INFO] Baseline: no BPF loaded")

        if phase == "baseline":
            return run_wrapper_with_perf(wrapper_path, wl_fn, perf_events, *wl_args, env=env)

        try:
            self._start_bpf(register_pid=register_pid)
        except Exception as e:
            print(f"  [WARN] BPF start failed: {e}")
            wall_s, _ = run_wrapper_workload(wrapper_path, wl_fn, *wl_args, env=env)
            return wall_s, {e: 0 for e in perf_events}

        # Run workload in bash subprocess (comm=bash, not auto-registered)
        wall_s, counts = run_wrapper_with_perf(wrapper_path, wl_fn, perf_events, *wl_args, env=env)

        # Keep loader running briefly so events flush to log/Redis before capture-rate read
        if phase == "fullcapture":
            time.sleep(1.0)

        return wall_s, counts

    def _start_bpf(self, register_pid=None):
        cfg_bpf = self.cfg.get("bpf", {})
        loader = cfg_bpf.get("loader_binary", "build/loader")
        ringbuf = cfg_bpf.get("ringbuf_handler_binary", "build/ringbuf_handler")
        ringbuf_log = cfg_bpf.get("ringbuf_log", "/tmp/perf_bench_ringbuf.log")
        loader_log = cfg_bpf.get("loader_log", "/tmp/perf_bench_loader.log")
        fifo_path = cfg_bpf.get("fifo_path", "/tmp/perf_bench_rb.fifo")

        # Clean up stale pin files (mirrors test_perf.sh start_loader_and_rb)
        for pin in ("/sys/fs/bpf/sys_rb", "/sys/fs/bpf/ssl_rb",
                    "/sys/fs/bpf/raw_rb", "/sys/fs/bpf/res_map"):
            try:
                os.unlink(pin)
            except Exception:
                pass

        # Clean up stale log/fifo files: root can delete files in sticky /tmp
        # even if owned by another user (avoids fs.protected_regular EACCES).
        for stale in (ringbuf_log, loader_log, fifo_path):
            try:
                os.unlink(stale)
            except Exception:
                pass

        # Kill any existing instances
        subprocess.run(["pkill", "-f", "loader"], stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "ringbuf_handler"], stderr=subprocess.DEVNULL)
        time.sleep(0.5)

        loader_cmd = ["stdbuf", "-oL", "-eL", loader]
        if register_pid:
            loader_cmd.append(str(register_pid))

        self._loader_log_fh = open(loader_log, "w")
        self._loader_proc = subprocess.Popen(
            loader_cmd, stdout=self._loader_log_fh, stderr=subprocess.STDOUT
        )

        # Wait up to 8s for BPF pipeline to pin (mirrors original)
        waited = 0
        while waited < 8:
            time.sleep(1)
            waited += 1
            if self._loader_proc.poll() is not None:
                print(f"  [WARN] loader exited prematurely")
                try:
                    print(open(loader_log).read()[-2000:])
                except Exception:
                    pass
                raise RuntimeError("loader exited prematurely")
            if os.path.exists("/sys/fs/bpf/sys_rb"):
                break
        if not os.path.exists("/sys/fs/bpf/sys_rb"):
            print(f"  [WARN] loader BPF not ready in 8s")
            try:
                print(open(loader_log).read()[-2000:])
            except Exception:
                pass
            raise RuntimeError("loader BPF not ready")

        # Start ringbuf_handler: stdout -> FIFO -> tr filter -> log (mirrors original)
        try:
            os.unlink(fifo_path)
        except Exception:
            pass
        os.mkfifo(fifo_path)
        self._fifo_path = fifo_path

        self._ringbuf_proc = subprocess.Popen(
            ["stdbuf", "-oL", "-eL", ringbuf],
            stdout=open(fifo_path, "w"),
            stderr=subprocess.STDOUT,
        )
        # tr '\0' '.' < FIFO > ringbuf.log  (avoid null-byte binary breaking grep)
        self._tr_proc = subprocess.Popen(
            ["stdbuf", "-oL", "tr", "\\0", "."],
            stdin=open(fifo_path, "r"),
            stdout=open(ringbuf_log, "w"),
        )
        time.sleep(1)

    def _stop_bpf(self):
        cfg_bpf = self.cfg.get("bpf", {})
        ringbuf_log = cfg_bpf.get("ringbuf_log", "/tmp/perf_bench_ringbuf.log")

        # Stop ringbuf gracefully with SIGINT first (mirrors original)
        ringbuf_proc = getattr(self, "_ringbuf_proc", None)
        if ringbuf_proc:
            try:
                ringbuf_proc.send_signal(signal.SIGINT)
            except Exception:
                pass
            waited = 0
            while ringbuf_proc.poll() is None and waited < 3:
                time.sleep(1)
                waited += 1
            try:
                ringbuf_proc.kill()
            except Exception:
                pass
            self._ringbuf_proc = None

        # Stop tr filter
        tr_proc = getattr(self, "_tr_proc", None)
        if tr_proc:
            try:
                tr_proc.terminate()
                tr_proc.wait(timeout=2)
            except Exception:
                try:
                    tr_proc.kill()
                except Exception:
                    pass
            self._tr_proc = None

        # Stop loader gracefully with SIGINT (mirrors original)
        loader_proc = getattr(self, "_loader_proc", None)
        if loader_proc:
            try:
                loader_proc.send_signal(signal.SIGINT)
            except Exception:
                pass
            time.sleep(1)
            try:
                loader_proc.kill()
            except Exception:
                pass
            try:
                loader_proc.wait(timeout=3)
            except Exception:
                pass
            self._loader_proc = None

        try:
            if getattr(self, "_loader_log_fh", None):
                self._loader_log_fh.close()
        except Exception:
            pass

        subprocess.run(["pkill", "-f", "loader"], stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "ringbuf_handler"], stderr=subprocess.DEVNULL)
        for pin in ("/sys/fs/bpf/sys_rb", "/sys/fs/bpf/ssl_rb",
                    "/sys/fs/bpf/raw_rb", "/sys/fs/bpf/res_map"):
            try:
                os.unlink(pin)
            except Exception:
                pass
        time.sleep(0.5)

    def _flush_redis(self, host, port):
        try:
            import redis as redispy
            client = redispy.Redis(host=host, port=port, socket_timeout=3)
            client.xtrim("inter:events", 0, approximate=False)
            client.xtrim("inter:messages", 0, approximate=False)
            client.xtrim("inter:anomalies", 0, approximate=False)
            client.delete("inter:agents")
            client.delete("inter:edges")
            for key in client.keys("inter:edge:*"):
                client.delete(key)
            for key in client.keys("ssl:chunk:*"):
                client.delete(key)
            client.close()
        except Exception:
            pass

    def _generate_reports(self, env):
        cfg_out = self.cfg.get("output", {})
        report_dir = cfg_out.get("report_dir", "./reports")
        raw_dir = cfg_out.get("raw_data_dir", "./reports/raw_data")
        prefix = cfg_out.get("report_prefix", "ebpf_perf_bench")
        report_dir = _ensure_writable(report_dir)
        raw_dir = _ensure_writable(raw_dir)

        env_info = {
            "kernel": env.kernel_version,
            "cpu": env.cpu_model,
            "cores": env.cpu_cores,
            "memory": env.total_memory_gb,
            "python": env.python_version,
            "bpf": env.bpf_enabled,
            "redis": f"{self.cfg.get('redis', {}).get('host', '127.0.0.1')}:{self.cfg.get('redis', {}).get('port', 6379)}",
        }

        overhead = self._results.get("overhead", {"tiers": {}})
        capture = self._results.get("capture", {"tiers": {}})
        ssl = self._results.get("ssl", {"tiers": {}})
        latency = self._results.get("latency", {"tiers": {}})
        accuracy = self._results.get("accuracy", {})

        generate_report(report_dir, env_info, self.cfg, self._tier_labels,
                        overhead, capture, ssl, latency, accuracy, prefix)

        if "csv" in self.cfg.get("output", {}).get("formats", []):
            generate_csv(raw_dir, dict(self._raw_csv), prefix)


def _median_overhead(metric_list: List[Dict]) -> Dict:
    if not metric_list:
        return {}
    keys = metric_list[0].keys()
    result = {}
    for k in keys:
        vals = sorted([m[k] for m in metric_list if m[k] is not None])
        if vals:
            result[k] = vals[len(vals) // 2]
        else:
            result[k] = None
    return result


def _median_capture(metric_list: List[Dict]) -> Dict:
    return _median_overhead(metric_list)


def _median_ssl(metric_list: List[Dict]) -> Dict:
    return _median_overhead(metric_list)


def _median_latency(metric_list: List[Dict]) -> Dict:
    if not metric_list:
        return {}
    keys = set()
    for m in metric_list:
        keys.update(m.keys())
    result = {}
    for k in keys:
        vals = [m.get(k, {}) for m in metric_list]
        if all(isinstance(v, dict) for v in vals):
            subkeys = set()
            for v in vals:
                subkeys.update(v.keys())
            result[k] = {}
            for sk in subkeys:
                svals = sorted([v.get(sk, 0) for v in vals])
                result[k][sk] = svals[len(svals) // 2]
        else:
            nvals = sorted([v for v in vals if isinstance(v, (int, float))])
            result[k] = nvals[len(nvals) // 2] if nvals else 0
    return result


def _ensure_writable(path: str) -> str:
    """Return path if writable, else fall back to /tmp (e.g. root-owned output dirs)."""
    import tempfile
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_test")
        with open(probe, "w") as f:
            f.write("x")
        os.unlink(probe)
        return path
    except Exception:
        fallback = os.path.join(tempfile.gettempdir(),
                                "perf_framework", os.path.basename(path))
        try:
            os.makedirs(fallback, exist_ok=True)
            print(f"[INFO] Output dir not writable ({path}), using: {fallback}")
            return fallback
        except Exception:
            return path


def main():
    parser = argparse.ArgumentParser(
        description="eBPF Multi-Agent Monitor — Performance Benchmark Runner"
    )
    parser.add_argument("--config", default=os.path.join(os.path.dirname(__file__),
                        "config", "benchmark.yaml"),
                        help="Path to benchmark config YAML")
    parser.add_argument("--full", action="store_true",
                        help="Run full benchmark (all tiers × all iterations)")
    parser.add_argument("--smoke", action="store_true",
                        help="Quick smoke test (L1 only, 1 iteration)")
    parser.add_argument("--accuracy-only", action="store_true",
                        help="Run only accuracy evaluation (no BPF needed)")
    parser.add_argument("--skip-bpf", action="store_true",
                        help="Skip BPF performance tests")
    parser.add_argument("--tiers", type=str, default=None,
                        help="Comma-separated tier names (e.g. light,heavy)")
    parser.add_argument("--iterations", type=int, default=None,
                        help="Override iteration count")
    parser.add_argument("--output", type=str, default=None,
                        help="Override output directory")

    args = parser.parse_args()

    runner = BenchmarkRunner(args.config)

    if args.output:
        runner.cfg.setdefault("output", {})["report_dir"] = args.output

    tier_filter = args.tiers.split(",") if args.tiers else None
    skip_bpf = args.skip_bpf

    if args.accuracy_only:
        skip_bpf = True
        runner.cfg["benchmark"]["iterations"] = 1

    runner.run(
        tiers_filter=tier_filter,
        iterations=args.iterations,
        skip_bpf=skip_bpf,
        skip_accuracy=args.skip_bpf and not args.accuracy_only,
        smoke=args.smoke,
    )


if __name__ == "__main__":
    main()
