#!/usr/bin/env python3
"""P1 benchmark: dense vs sparse structure decoding on large graphs.

Builds a large random graph and runs AnomalyDetector.compute_anomaly_scores
once in dense (default) and once in sparse_struct mode, reporting wall time,
peak process memory (psutil), and score sanity (dense vs sparse both bounded).
"""
import os
import sys
import time

import numpy as np
import torch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, BASE)

from inter_agent.detection.gnn_detector import DOMINANT

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
E = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
F = 30
D = 6


def make_graph(n, e):
    torch.manual_seed(0)
    x = torch.randn(n, F)
    src = torch.randint(0, n, (e,))
    dst = torch.randint(0, n, (e,))
    edge_index = torch.stack([src, dst], dim=0)
    edge_attr = torch.rand(e, D)
    return x, edge_index, edge_attr


def peak_mb():
    import psutil
    return psutil.Process(os.getpid()).memory_info().rss / 1e6


class RssSampler:
    """Background thread sampling peak RSS while a function runs."""

    def __init__(self):
        import psutil
        self._proc = psutil.Process(os.getpid())
        self._peak = 0.0
        self._stop = False

    def start(self):
        import threading
        self._stop = False
        self._peak = 0.0

        def _loop():
            while not self._stop:
                self._peak = max(self._peak,
                                 self._proc.memory_info().rss / 1e6)
                time.sleep(0.002)
        self._t = threading.Thread(target=_loop, daemon=True)
        self._t.start()

    def stop(self):
        self._stop = True
        self._t.join(timeout=0.2)
        return self._peak


def run(det, label, x, edge_index, edge_attr):
    torch.manual_seed(0)
    sampler = RssSampler()
    sampler.start()
    t0 = time.time()
    scores, feat, struct, edge_err, z = det.compute_anomaly_scores(
        x, edge_index, edge_attr=edge_attr, topology="hierarchical")
    dt = time.time() - t0
    peak = sampler.stop()
    print(f"  {label:8s} N={N:<6d} E={E:<7d} time={dt:6.2f}s  peak_mem={peak:8.1f} MB"
          f"  score_range=[{scores.min():.4f},{scores.max():.4f}]"
          f"  mean_struct_err={struct:.4f}")
    return dt, peak, scores


if __name__ == "__main__":
    x, edge_index, edge_attr = make_graph(N, E)
    dense_nbytes = N * N * 8 / 1e6
    sparse_nbytes = 2 * E * 8 / 1e6 + N * 8
    print(f"Graph: N={N}, E={E}")
    print(f"  dense adjacency matrix: {dense_nbytes:.1f} MB (fp64) |"
          f"  {N*N*4/1e6:.1f} MB (fp32)")
    print(f"  sparse edge storage:    {sparse_nbytes:.1f} MB")
    print()

    print("Dense (default):")
    det_dense = DOMINANT(in_dim=F, hidden_dim=64, latent_dim=64,
                         edge_dim=D, sparse_struct=False)
    dt_d, mem_d, sc_d = run(det_dense, "dense", x, edge_index, edge_attr)

    print("Sparse (P1):")
    det_sparse = DOMINANT(in_dim=F, hidden_dim=64, latent_dim=64,
                          edge_dim=D, sparse_struct=True)
    dt_s, mem_s, sc_s = run(det_sparse, "sparse", x, edge_index, edge_attr)

    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  dense : {dt_d:6.2f}s   peak {mem_d:8.1f} MB")
    print(f"  sparse: {dt_s:6.2f}s   peak {mem_s:8.1f} MB")
    print(f"  time speedup : {dt_d / max(dt_s, 1e-9):.1f}x")
    print(f"  mem reduction: {mem_d / max(mem_s, 1e-9):.1f}x  ({(mem_d - mem_s):.0f} MB saved)")
    print(f"  sparse/dense score correlation: "
          f"{np.corrcoef(sc_d, sc_s)[0, 1]:.4f}")
