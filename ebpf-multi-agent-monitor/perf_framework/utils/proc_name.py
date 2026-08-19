import ctypes
import os

_PR_SET_NAME = 15
_MAX_COMM_LEN = 16


def rename_comm(name: str = "bench_runner"):
    """Rename the current process comm (<=15 chars) via prctl(PR_SET_NAME).

    This prevents the kernel-side BPF `try_auto_register` (which matches
    comm starting with "python"/"claude"/"node"/"bun") from auto-registering
    the benchmark runner — the root cause of the feedback loop where the
    runner's children (ringbuf_handler) inherited monitoring.
    """
    if not name or len(name) >= _MAX_COMM_LEN:
        raise ValueError(f"comm name must be 1-15 chars, got {len(name)}")

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        buf = name.encode("ascii")
        ret = libc.prctl(_PR_SET_NAME, buf, 0, 0, 0)
        if ret != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) failed")
    except Exception:
        # Non-fatal: if comm rename fails, fall back to running under a
        # bash-wrapped command (comm becomes "bash").
        pass

    return current_comm()


def current_comm() -> str:
    try:
        with open("/proc/self/comm") as f:
            return f.read().strip()
    except Exception:
        return "unknown"
