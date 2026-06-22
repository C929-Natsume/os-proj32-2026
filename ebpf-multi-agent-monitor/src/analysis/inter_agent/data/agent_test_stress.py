"""System call stress process for eBPF baseline calibration.

Generates a mix of realistic syscalls (HTTP requests, file I/O, process exec)
so that the eBPF pipeline (loader + ringbuf_handler) has data to capture.

The filename contains 'agent_test' so loader's PID auto-discovery matches it.
Redis will accumulate per-agent metrics over 30-second windows.

Usage:
    python -m inter_agent.data.agent_test_stress --duration 300 --workers 3

Run this while data_recorder is polling Redis.
"""

import argparse
import logging
import os
import subprocess
import time
import urllib.request

logger = logging.getLogger(__name__)


def _http_task(task_id: int):
    """Make an HTTPS request to generate SSL_read/SSL_write traffic."""
    urls = [
        "https://example.com/",
        "https://www.google.com/",
    ]
    url = urls[task_id % len(urls)]
    try:
        urllib.request.urlopen(url, timeout=5)
    except Exception:
        pass


def _file_task(tmp_dir: str, task_id: int):
    """Read/write files in a temp directory."""
    path = os.path.join(tmp_dir, f"stress_{task_id % 5}.txt")
    with open(path, "a") as f:
        f.write(f"data_{task_id}\n" * 50)
    with open(path, "r") as f:
        _ = f.read()
    if task_id % 7 == 0:
        try:
            os.unlink(path)
        except OSError:
            pass


def _exec_task(task_id: int):
    """Execute lightweight shell commands."""
    cmds = [
        ["echo", f"agent_test_stress_{task_id}"],
        ["ls", "/tmp"],
        ["cat", "/proc/uptime"],
        ["hostname"],
    ]
    cmd = cmds[task_id % len(cmds)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=5)
    except Exception:
        pass


def stress_loop(duration: int = 300, workers: int = 3, interval: float = 1.0):
    """Run a mix of syscall-generating tasks for `duration` seconds.

    Each iteration round-robins through HTTP, file I/O, and exec tasks.
    The mix mimics what AutoGen agents do (API calls, file ops, tools).
    """
    tmp_dir = f"/tmp/agent_test_stress_{os.getpid()}"
    os.makedirs(tmp_dir, exist_ok=True)

    logger.info("Stress loop starting: duration=%ds, workers=%d, pid=%d",
                duration, workers, os.getpid())
    logger.info("PID %d — loader should auto-discover this process", os.getpid())

    task_id = 0
    start_ts = time.time()
    while time.time() - start_ts < duration:
        for w in range(workers):
            base = task_id * workers + w
            _http_task(base)
            _file_task(tmp_dir, base)
            _exec_task(base)
            task_id += 1
        time.sleep(interval)

    logger.info("Stress loop done: %d tasks in %.1fs",
                task_id, time.time() - start_ts)

    for f in os.listdir(tmp_dir):
        try:
            os.unlink(os.path.join(tmp_dir, f))
        except OSError:
            pass
    os.rmdir(tmp_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Generate syscall load for eBPF baseline calibration"
    )
    parser.add_argument("--duration", type=int, default=300,
                        help="Run duration in seconds")
    parser.add_argument("--workers", type=int, default=3,
                        help="Concurrent task workers per iteration")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Seconds between task batches")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[STRESS] %(message)s",
    )
    stress_loop(
        duration=args.duration,
        workers=args.workers,
        interval=args.interval,
    )


if __name__ == "__main__":
    main()
