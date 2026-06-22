"""Orchestrator: stress process → eBPF capture → .jsonl recording.

Launches the full data collection pipeline and cleans up on completion.
Designed to run directly on the Ubuntu VM (BPF requires Linux).

Usage:
    python -m inter_agent.data.agent_test_collect                \
        --duration 120       \   : stress duration (seconds)
        --workers 3          \   : stress worker count
        --inject-rate 0.1    \   : anomaly injection rate for data_recorder
        --sudo-password huster   : sudo password for BPF binaries (optional)
"""

import argparse
import logging
import os
import signal
import subprocess
import sys
import time

logger = logging.getLogger(__name__)


BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER_BIN = os.path.join(os.path.dirname(os.path.dirname(BASE)), "user")
PIPELINE_DIR = os.path.join(os.path.dirname(os.path.dirname(BASE)), "pipeline")


def _sudo_popen(cmd: list, password: str = None, **kwargs):
    """Run a command with sudo, password via stdin if provided."""
    if password:
        full_cmd = "echo {pwd} | sudo -S {bin}".format(pwd=password, bin=" ".join(cmd))
        return subprocess.Popen(full_cmd, shell=True, **kwargs)
    else:
        return subprocess.Popen(["sudo", "-n"] + cmd, **kwargs)


def _start_pipeline(password: str = None) -> list:
    """Start loader + ringbuf_handler as background subprocesses (sudo)."""
    procs = []

    # Start ringbuf_handler first (it connects to Redis and waits for data)
    ringbuf_path = os.path.join(USER_BIN, "ringbuf_handler")
    if os.path.exists(ringbuf_path):
        log_fp = open("/tmp/ringbuf_handler.log", "w")
        p = _sudo_popen([ringbuf_path], password=password,
                        stdout=log_fp, stderr=subprocess.STDOUT,
                        start_new_session=True)
        procs.append((p, log_fp))
        logger.info("ringbuf_handler started (pid=%d)", p.pid)
    else:
        logger.warning("ringbuf_handler not found at %s — skipping", ringbuf_path)

    # Start loader (auto-discovers agent_test processes)
    loader_path = os.path.join(USER_BIN, "loader")
    if os.path.exists(loader_path):
        log_fp = open("/tmp/loader.log", "w")
        p = _sudo_popen([loader_path], password=password,
                        stdout=log_fp, stderr=subprocess.STDOUT,
                        start_new_session=True)
        procs.append((p, log_fp))
        logger.info("loader started (pid=%d)", p.pid)
    else:
        logger.warning("loader not found at %s — skipping", loader_path)

    if not procs:
        logger.warning("No BPF binaries found — running without eBPF capture")

    return procs


def _stop_pipeline(procs: list[subprocess.Popen]):
    """Gracefully stop pipeline processes."""
    for p, log_fp in reversed(procs):
        if p.poll() is None:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                p.wait()
        log_fp.close()

    logger.info("Pipeline stopped (%d processes)", len(procs))


def main():
    parser = argparse.ArgumentParser(
        description="Orchestrate eBPF data collection for GNN baseline calibration"
    )
    parser.add_argument("--duration", type=int, default=120,
                        help="Stress duration in seconds")
    parser.add_argument("--workers", type=int, default=3,
                        help="Stress worker count")
    parser.add_argument("--inject-rate", type=float, default=0.1,
                        help="Anomaly injection rate for data_recorder")
    parser.add_argument("--redis-host", default="127.0.0.1",
                        help="Redis host")
    parser.add_argument("--redis-port", type=int, default=6379,
                        help="Redis port")
    parser.add_argument("--output-dir", default="captured",
                        help="Output directory for .jsonl files")
    parser.add_argument("--output-file", default=None,
                        help="Output .jsonl filename (default: auto-generated)")
    parser.add_argument("--no-bpf", action="store_true",
                        help="Skip starting BPF pipeline (for testing collector only)")
    parser.add_argument("--sudo-password", default=None,
                        help="Password for sudo (BPF binaries need root)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="[COLLECT] %(asctime)s %(message)s")

    os.makedirs(args.output_dir, exist_ok=True)

    # ── 1. start data_recorder ─────────────────────────────────────────
    if args.output_file:
        output_path = os.path.join(args.output_dir, args.output_file)
    else:
        ts = time.strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(args.output_dir, f"capture_{ts}.jsonl")

    recorder_log = open(os.path.join(args.output_dir, "recorder.log"), "w")
    recorder_proc = subprocess.Popen(
        [
            sys.executable, "-m", "inter_agent.data.data_recorder",
            "--redis-host", args.redis_host,
            "--redis-port", str(args.redis_port),
            "--output", output_path,
            "--duration", str(args.duration + 30),
            "--inject-rate", str(args.inject_rate),
        ],
        stdout=recorder_log, stderr=subprocess.STDOUT,
        cwd=os.path.dirname(BASE),
        start_new_session=True,
    )
    logger.info("data_recorder started (pid=%d, output=%s)",
                recorder_proc.pid, args.output_dir)

    # ── 2. start BPF pipeline ──────────────────────────────────────────
    pipeline_procs = _start_pipeline(password=args.sudo_password) if not args.no_bpf else []

    # ── 3. wait for bootstrapping ──────────────────────────────────────
    logger.info("Waiting 5s for pipeline bootstrapping...")
    time.sleep(5)

    # ── 4. start stress process ────────────────────────────────────────
    logger.info("Starting stress process (duration=%ds, workers=%d)...",
                args.duration, args.workers)
    stress_proc = subprocess.Popen(
        [
            sys.executable, "-m", "inter_agent.data.agent_test_stress",
            "--duration", str(args.duration),
            "--workers", str(args.workers),
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=os.path.dirname(BASE),
        start_new_session=True,
    )

    # ── 5. wait for stress to complete ─────────────────────────────────
    stress_proc.wait()
    logger.info("Stress completed (exit=%d)", stress_proc.returncode)

    # ── 6. wait a bit for recorder to flush ────────────────────────────
    logger.info("Waiting 10s for data_recorder to flush remaining data...")
    time.sleep(10)

    # ── 7. stop everything ─────────────────────────────────────────────
    if recorder_proc.poll() is None:
        os.killpg(os.getpgid(recorder_proc.pid), signal.SIGTERM)
        try:
            recorder_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(recorder_proc.pid), signal.SIGKILL)
            recorder_proc.wait()
    recorder_log.close()

    _stop_pipeline(pipeline_procs)

    # ── 8. report results ──────────────────────────────────────────────
    import glob
    # Search both relative path and absolute (analysis) path
    jsonl_files = sorted(glob.glob(os.path.join(args.output_dir, "*.jsonl")))
    if not jsonl_files:
        jsonl_files = sorted(glob.glob(os.path.join(os.path.dirname(BASE), args.output_dir, "*.jsonl")))
    if jsonl_files:
        total_lines = 0
        for fp in jsonl_files:
            with open(fp) as f:
                n = sum(1 for _ in f)
            total_lines += n
            logger.info("  %s (%d lines)", fp, n)
        logger.info("Total: %d files, %d observations", len(jsonl_files), total_lines)
    else:
        logger.warning("No .jsonl files found in %s", args.output_dir)

    logger.info("Collection complete — output: %s", args.output_dir)


if __name__ == "__main__":
    main()
