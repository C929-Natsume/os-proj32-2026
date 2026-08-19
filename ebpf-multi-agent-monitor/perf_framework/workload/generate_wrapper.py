import os
import shutil
import subprocess
import tempfile
from typing import Optional

_WRAPPER_SRC = os.path.join(os.path.dirname(__file__), "wrapper.sh")


def get_wrapper_script() -> str:
    """Return path to the bash workload wrapper script.

    Uses a unique per-run temp path (mkstemp) to avoid the sticky-directory
    overwrite protection (fs.protected_regular=2) which blocks even root from
    overwriting a file owned by another user in /tmp.
    """
    fd, dst = tempfile.mkstemp(prefix="perf_bench_wrapper_", suffix=".sh")
    with os.fdopen(fd, "w") as f:
        with open(_WRAPPER_SRC, "r") as src:
            f.write(src.read())
    os.chmod(dst, 0o755)
    return dst


def run_wrapper_workload(wrapper_path: str, fn: str, *args,
                         env: Optional[dict] = None) -> float:
    """Run a workload function in the bash wrapper. Returns wall-clock seconds."""
    import time
    cmd = ["bash", wrapper_path, fn] + list(args)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    t0 = time.perf_counter()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env=merged_env, timeout=180)
    return time.perf_counter() - t0


def run_wrapper_with_perf(wrapper_path: str, fn: str, perf_events,
                          *args, env: Optional[dict] = None):
    """Run a workload under `perf stat -- bash wrapper.sh`. Returns (wall_s, counts)."""
    import time
    from perf_framework.metrics.ebpf_overhead import _parse_perf_stat

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    event_list = ",".join(perf_events)
    cmd = ["perf", "stat", "-e", event_list, "--", "bash", wrapper_path, fn] + list(args)
    t0 = time.perf_counter()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                env=merged_env, timeout=300)
    except Exception:
        # perf unavailable — fall back to plain timing
        import shutil as _shutil
        if _shutil.which("perf") is None:
            t0 = time.perf_counter()
            subprocess.run(["bash", wrapper_path, fn] + list(args),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env=merged_env, timeout=180)
            return time.perf_counter() - t0, {e: 0 for e in perf_events}
        raise
    wall = time.perf_counter() - t0
    counts = _parse_perf_stat(result.stderr, perf_events)
    return wall, counts
