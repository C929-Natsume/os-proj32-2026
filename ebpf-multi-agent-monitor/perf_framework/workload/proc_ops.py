import os
import time
import random
import subprocess


def _safe_exec_shell(cmd: str, timeout: float = 2.0):
    try:
        subprocess.run(cmd, shell=True, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def fork_workload(count: int = 10):
    for _ in range(count):
        pid = os.fork()
        if pid == 0:
            time.sleep(random.uniform(0.001, 0.005))
            os._exit(0)
        else:
            try:
                os.waitpid(pid, 0)
            except Exception:
                pass


def exec_workload(count: int = 5):
    cmds = [
        "cat /proc/self/stat",
        "uname -a",
        "hostname",
        "pwd",
        "id -u",
        "date +%s",
        "wc -c /proc/self/cmdline",
        "ls /tmp",
    ]
    for _ in range(count):
        cmd = random.choice(cmds)
        _safe_exec_shell(cmd, timeout=1.0)


def combined_proc_workload(forks: int = 10, execs: int = 5):
    fork_workload(forks)
    exec_workload(execs)
