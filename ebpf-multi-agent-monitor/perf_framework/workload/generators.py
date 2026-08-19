import time
import concurrent.futures
from typing import Dict, Optional

from .file_ops import file_io_workload, file_io_batch
from .net_ops import network_workload
from .proc_ops import combined_proc_workload, exec_workload, fork_workload
from .ssl_ops import ssl_workload


def run_tier_workload(tier: Dict, enable_ssl: bool = True):
    """Run a single tier workload and return wall-clock duration."""
    t0 = time.perf_counter()
    file_iter = tier.get("file_iterations", 100)
    net_msgs = tier.get("net_messages", 20)
    fork_n = tier.get("fork_count", 10)
    exec_n = tier.get("exec_count", 5)
    ssl_n = tier.get("ssl_requests", 10)
    parallelism = tier.get("parallelism", 1)

    if parallelism > 1:
        _run_parallel(tier)
    else:
        file_io_workload(file_iter)
        if net_msgs > 0:
            network_workload(net_msgs, port=19999)
        combined_proc_workload(forks=fork_n, execs=exec_n)
        if enable_ssl and ssl_n > 0:
            ssl_workload(ssl_n)

    return time.perf_counter() - t0


def _run_parallel(tier: Dict):
    parallelism = tier.get("parallelism", 1)
    file_iter = tier.get("file_iterations", 100) // parallelism
    fork_n = tier.get("fork_count", 10) // parallelism
    exec_n = tier.get("exec_count", 5) // parallelism
    net_msgs = tier.get("net_messages", 20) // parallelism
    ssl_n = tier.get("ssl_requests", 10) // parallelism

    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as pool:
        futures = []
        for _ in range(parallelism):
            if file_iter > 0:
                futures.append(pool.submit(file_io_workload, file_iter))
            if fork_n > 0:
                futures.append(pool.submit(fork_workload, fork_n))
            if exec_n > 0:
                futures.append(pool.submit(exec_workload, exec_n))
            if net_msgs > 0:
                futures.append(pool.submit(network_workload, net_msgs))
            if ssl_n > 0:
                futures.append(pool.submit(ssl_workload, ssl_n))
        concurrent.futures.wait(futures, timeout=120)
