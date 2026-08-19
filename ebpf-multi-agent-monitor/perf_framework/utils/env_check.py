import os
import sys
import subprocess
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class EnvReport:
    root_ok: bool
    bpftool_ok: bool
    redis_ok: bool
    loader_exists: bool
    ringbuf_handler_exists: bool
    python_version: str
    kernel_version: str
    cpu_model: str
    cpu_cores: int
    total_memory_gb: float
    bpf_enabled: bool
    errors: List[str] = field(default_factory=list)

def check_environment(loader_path: str, ringbuf_path: str,
                      redis_host: str, redis_port: int) -> EnvReport:
    r = EnvReport(
        root_ok=(os.geteuid() == 0),
        bpftool_ok=shutil.which("bpftool") is not None,
        redis_ok=False,
        loader_exists=os.path.exists(loader_path),
        ringbuf_handler_exists=os.path.exists(ringbuf_path),
        python_version=sys.version.split()[0],
        kernel_version="unknown",
        cpu_model="unknown",
        cpu_cores=0,
        total_memory_gb=0.0,
        bpf_enabled=False,
    )

    if not r.root_ok:
        r.errors.append("Not running as root — eBPF operations require sudo")

    if not r.bpftool_ok:
        r.errors.append("bpftool not found in PATH — install bpftool")

    if not r.loader_exists:
        r.errors.append(f"Loader binary not found: {loader_path}")

    if not r.ringbuf_handler_exists:
        r.errors.append(f"Ringbuf handler binary not found: {ringbuf_path}")

    # Kernel version
    try:
        r.kernel_version = subprocess.check_output(
            ["uname", "-r"], text=True
        ).strip()
    except Exception:
        r.errors.append("Failed to get kernel version")

    # CPU info
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    r.cpu_model = line.split(":", 1)[1].strip()
                    break
        with open("/proc/cpuinfo") as f:
            r.cpu_cores = sum(1 for l in f if l.startswith("processor"))
    except Exception:
        r.errors.append("Failed to read /proc/cpuinfo")

    # Memory
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    r.total_memory_gb = kb / 1048576.0
                    break
    except Exception:
        r.errors.append("Failed to read /proc/meminfo")

    # BPF
    try:
        r.bpf_enabled = os.path.exists("/sys/kernel/btf/vmlinux")
    except Exception:
        pass
    if not r.bpf_enabled:
        r.errors.append("CONFIG_DEBUG_INFO_BTF not available — BPF CO-RE requires it")

    # Redis ping
    try:
        import redis as redispy
        client = redispy.Redis(host=redis_host, port=redis_port, socket_timeout=3)
        client.ping()
        r.redis_ok = True
        client.close()
    except Exception as e:
        r.errors.append(f"Redis not reachable at {redis_host}:{redis_port}: {e}")

    return r

def print_env_report(r: EnvReport):
    def _status(ok): return "OK" if ok else "FAIL"
    lines = [
        "=" * 60,
        "  Environment Check",
        "=" * 60,
        f"  Root privileges:      {_status(r.root_ok)}",
        f"  bpftool:              {_status(r.bpftool_ok)}",
        f"  Redis:                {_status(r.redis_ok)}",
        f"  Loader binary:        {_status(r.loader_exists)}",
        f"  Ringbuf handler:      {_status(r.ringbuf_handler_exists)}",
        f"  BPF enabled:          {_status(r.bpf_enabled)}",
        f"  Python:               {r.python_version}",
        f"  Kernel:               {r.kernel_version}",
        f"  CPU:                  {r.cpu_model} ({r.cpu_cores} cores)",
        f"  Memory:               {r.total_memory_gb:.1f} GB",
    ]
    if r.errors:
        lines.append("  --- Errors ---")
        for e in r.errors:
            lines.append(f"  * {e}")
    lines.append("=" * 60)
    print("\n".join(lines))
