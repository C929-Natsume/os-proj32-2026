import os
import subprocess
from typing import Optional

def get_current_governor() -> Optional[str]:
    try:
        path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None

def set_governor(governor: str = "performance"):
    for cpu_path in _cpu_freq_dirs():
        gov_path = os.path.join(cpu_path, "scaling_governor")
        if os.path.exists(gov_path):
            try:
                with open(gov_path, "w") as f:
                    f.write(governor)
            except Exception:
                pass

def lock_frequency(ghz: float = 2.0):
    freq_khz = int(ghz * 1_000_000)
    if subprocess.call(["which", "cpupower"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        subprocess.run(
            ["cpupower", "frequency-set", "-d", f"{freq_khz}kHz", "-u", f"{freq_khz}kHz"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    else:
        for cpu_path in _cpu_freq_dirs():
            try:
                min_path = os.path.join(cpu_path, "scaling_min_freq")
                max_path = os.path.join(cpu_path, "scaling_max_freq")
                if os.path.exists(min_path):
                    with open(min_path, "w") as f:
                        f.write(str(freq_khz))
                if os.path.exists(max_path):
                    with open(max_path, "w") as f:
                        f.write(str(freq_khz))
            except Exception:
                pass

def get_current_freq() -> Optional[float]:
    try:
        path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
        with open(path) as f:
            return int(f.read().strip()) / 1_000_000.0
    except Exception:
        return None

def _cpu_freq_dirs():
    base = "/sys/devices/system/cpu"
    dirs = []
    for entry in sorted(os.listdir(base)):
        if entry.startswith("cpu") and entry[3:].isdigit():
            cpufreq = os.path.join(base, entry, "cpufreq")
            if os.path.isdir(cpufreq):
                dirs.append(cpufreq)
    return dirs
