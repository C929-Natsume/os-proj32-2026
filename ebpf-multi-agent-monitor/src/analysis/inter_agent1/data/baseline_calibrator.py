"""Baseline calibrator 鈥?fits distributions from real eBPF observations.

Captured data (via DataRecorder) serves as the statistical baseline.
The calibrator preserves the *covariance structure* between fields
that real eBPF data produces (e.g., cpu_usage鈫?correlates with
proc_exec_count鈫?, then generates arbitrarily many training samples
with correct multivariate statistics.

Now supports variable agent counts, diverse topologies, causal edge
generation, and multi-level anomaly injection.

Usage:
    calibrator = BaselineCalibrator()
    calibrator.fit("captured/normal.jsonl")

    normal = calibrator.generate_normal(num=500)
    anomaly = calibrator.generate_anomaly(num=100)
"""

import json
import logging
import math
import os
import random
from typing import Optional

import numpy as np

from inter_agent.data.data_recorder import DataRecorder

logger = logging.getLogger(__name__)

ALL_TOPOLOGIES = [
    "hierarchical", "peer-to-peer", "chain", "tree", "ring", "scale_free", "random",
]

# 鈹€鈹€ field definitions (mirrors collector.py + gnn_detector.py) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

INT_FIELDS = [
    "proc_exec_count", "proc_fork_count", "fs_open_count",
    "fs_read_count", "fs_write_count", "fs_unlink_count",
    "net_connect_count", "net_send_count", "net_recv_count",
    "api_call_count", "msg_sent", "msg_received",
    "unique_files_count",
    "ssl_msg_count", "ssl_total_bytes",
]

# Auto-generated temporal delta/accel fields (added by collector.py)
TEMP_FIELDS = [f + s for f in [
    "proc_exec_count", "proc_fork_count", "fs_open_count",
    "fs_read_count", "fs_write_count", "fs_unlink_count",
    "net_connect_count", "net_send_count", "net_recv_count",
    "api_call_count", "msg_sent", "msg_received",
    "unique_files_count", "shell_exec_count",
    "sensitive_file_count",
    "ssl_msg_count", "ssl_total_bytes",
] for s in ("_delta", "_accel")]

TEMP_FLOAT_FIELDS = [f + s for f in ["cpu_usage", "memory_usage"] for s in ("_delta", "_accel")]

ZERO_INFLATED_FIELDS = [
    "shell_exec_count", "sensitive_file_count",
]

FLOAT_FIELDS = ["cpu_usage", "memory_usage"]

ALL_FIELDS = INT_FIELDS + FLOAT_FIELDS + ZERO_INFLATED_FIELDS + TEMP_FIELDS + TEMP_FLOAT_FIELDS


# 鈹€鈹€ helpers 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def _to_field_array(observations, filter_zero=False):
    """Extract per-agent metrics from observations into [N, F] arrays.

    Uses whatever agent IDs are present in the data (dynamic detection).
    When filter_zero=True, rows where all 17 fields are 0 are excluded.
    """
    rows = []
    for obs in observations:
        agents = obs.get("agents", {})
        if not agents:
            continue
        for aid, info in agents.items():
            row = []
            for f in ALL_FIELDS:
                row.append(float(info.get(f, 0)))
            if filter_zero and all(v == 0.0 for v in row):
                continue
            rows.append(row)
    return np.array(rows, dtype=np.float64)


def _clip_generated(x, field_idx, n_int):
    """Clip generated values to valid ranges per field type."""
    fidx = field_idx
    n_float = len(FLOAT_FIELDS)
    n_zi = len(ZERO_INFLATED_FIELDS)
    n_temp = len(TEMP_FIELDS)
    n_tempf = len(TEMP_FLOAT_FIELDS)
    if fidx < n_int:
        return max(0, int(round(x)))
    elif fidx < n_int + n_float:
        return float(np.clip(x, 0.0, 1.0))
    elif fidx < n_int + n_float + n_zi:
        return max(0, int(round(x)))
    elif fidx < n_int + n_float + n_zi + n_temp:
        return int(round(x))  # temporal delta/accel can be negative
    else:
        return float(x)  # temporal float delta/accel


# 鈹€鈹€ topology builders 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def _build_topology_hierarchical(agent_ids, rng, metrics_dict=None):
    """Star: supervisor=agent_0, workers=others. 2*(N-1) edges."""
    n = len(agent_ids)
    if n < 2:
        return []
    supervisor = agent_ids[0]
    workers = agent_ids[1:]
    interactions = []
    for w in workers:
        weight = round(rng.uniform(0.5, 0.9), 3)
        interactions.append({
            "src": supervisor, "dst": w,
            "type": rng.choice(["api_call", "message"]),
            "weight": weight,
        })
        weight_b = round(rng.uniform(0.2, 0.5), 3)
        interactions.append({
            "src": w, "dst": supervisor,
            "type": "message",
            "weight": weight_b,
        })
    return interactions


def _build_topology_peer_to_peer(agent_ids, rng, metrics_dict=None):
    """Full mesh: every pair bidirectional. N*(N-1) edges."""
    n = len(agent_ids)
    interactions = []
    for i in range(n):
        for j in range(n):
            if i < j:
                weight = round(rng.uniform(0.3, 0.7), 3)
                src, dst = agent_ids[i], agent_ids[j]
                interactions.append({
                    "src": src, "dst": dst,
                    "type": rng.choice(["message", "api_call"]),
                    "weight": weight,
                })
                interactions.append({
                    "src": dst, "dst": src,
                    "type": "message",
                    "weight": weight,
                })
    return interactions


def _build_topology_chain(agent_ids, rng, metrics_dict=None):
    """Linear chain. 2*(N-1) edges (bidirectional)."""
    n = len(agent_ids)
    interactions = []
    for i in range(n - 1):
        src, dst = agent_ids[i], agent_ids[i + 1]
        weight_fwd = round(rng.uniform(0.4, 0.8), 3)
        interactions.append({
            "src": src, "dst": dst,
            "type": rng.choice(["message", "api_call"]),
            "weight": weight_fwd,
        })
        weight_bwd = round(rng.uniform(0.3, 0.6), 3)
        interactions.append({
            "src": dst, "dst": src,
            "type": "message",
            "weight": weight_bwd,
        })
    return interactions


def _build_topology_tree(agent_ids, rng, metrics_dict=None):
    """Binary tree: root=agent_0 level by level. 2*(N-1) edges."""
    n = len(agent_ids)
    interactions = []
    for i in range(1, n):
        parent = agent_ids[(i - 1) // 2]
        child = agent_ids[i]
        weight = round(rng.uniform(0.4, 0.8), 3)
        interactions.append({
            "src": parent, "dst": child,
            "type": rng.choice(["api_call", "message"]),
            "weight": weight,
        })
        interactions.append({
            "src": child, "dst": parent,
            "type": "message",
            "weight": round(rng.uniform(0.2, 0.5), 3),
        })
    return interactions


def _build_topology_ring(agent_ids, rng, metrics_dict=None):
    """Circular ring. 2*N edges."""
    n = len(agent_ids)
    interactions = []
    for i in range(n):
        j = (i + 1) % n
        src, dst = agent_ids[i], agent_ids[j]
        interactions.append({
            "src": src, "dst": dst,
            "type": rng.choice(["message", "api_call"]),
            "weight": round(rng.uniform(0.3, 0.7), 3),
        })
        interactions.append({
            "src": dst, "dst": src,
            "type": "message",
            "weight": round(rng.uniform(0.2, 0.5), 3),
        })
    return interactions


def _build_topology_scale_free(agent_ids, rng, metrics_dict=None):
    """Preferential attachment (Barab谩si鈥揂lbert). ~2*N edges."""
    n = len(agent_ids)
    if n < 2:
        return []
    degrees = [0] * n
    interactions = []
    # start with 2 connected nodes
    connections = [0]
    for i in range(1, n):
        # connect node i to existing nodes with probability proportional to degree
        total = sum(degrees[:i]) or 1
        for j_idx, j in enumerate(connections[:i]):
            pref = (degrees[j] + 1) / (total + i)
            if rng.random() < pref:
                src, dst = agent_ids[i], agent_ids[j]
                weight = round(rng.uniform(0.3, 0.8), 3)
                interactions.append({
                    "src": src, "dst": dst,
                    "type": rng.choice(["message", "api_call"]),
                    "weight": weight,
                })
                interactions.append({
                    "src": dst, "dst": src,
                    "type": "message",
                    "weight": round(rng.uniform(0.2, 0.5), 3),
                })
                degrees[i] += 1
                degrees[j] += 1
        connections.append(i)
    return interactions


def _build_topology_random(agent_ids, rng, metrics_dict=None):
    """Erdos-Renyi random graph with p=0.4. Expected ~0.4*N*(N-1) edges."""
    n = len(agent_ids)
    interactions = []
    for i in range(n):
        for j in range(n):
            if i < j and rng.random() < 0.4:
                src, dst = agent_ids[i], agent_ids[j]
                weight = round(rng.uniform(0.3, 0.7), 3)
                interactions.append({
                    "src": src, "dst": dst,
                    "type": rng.choice(["message", "api_call"]),
                    "weight": weight,
                })
                interactions.append({
                    "src": dst, "dst": src,
                    "type": "message",
                    "weight": round(rng.uniform(0.2, 0.5), 3),
                })
    return interactions


TOPOLOGY_BUILDERS = {
    "hierarchical": _build_topology_hierarchical,
    "peer-to-peer": _build_topology_peer_to_peer,
    "chain": _build_topology_chain,
    "tree": _build_topology_tree,
    "ring": _build_topology_ring,
    "scale_free": _build_topology_scale_free,
    "random": _build_topology_random,
}


def _apply_causal_edges(interactions, agent_ids, fields_list, rng, strength=1.0):
    """Filter interactions: keep edge with probability sigmoid(尾路metrics).

    This creates a causal link between agent metrics and graph structure.
    Agents with high api_call_count / msg_sent are more likely to have edges.
    """
    if strength <= 0:
        return interactions
    n = len(agent_ids)
    id_to_idx = {aid: i for i, aid in enumerate(agent_ids)}
    kept = []
    for edge in interactions:
        src = id_to_idx[edge["src"]]
        dst = id_to_idx[edge["dst"]]
        m_s = fields_list[src]
        m_d = fields_list[dst]
        api_s = m_s.get("api_call_count", 0)
        msg_s = m_s.get("msg_sent", 0) + m_s.get("msg_received", 0)
        api_d = m_d.get("api_call_count", 0)
        msg_d = m_d.get("msg_sent", 0) + m_d.get("msg_received", 0)
        logit = -1.5 + strength * 0.05 * (api_s + api_d + msg_s + msg_d)
        p = 1.0 / (1.0 + math.exp(-logit))
        p = min(max(p, 0.05), 0.95)
        if rng.random() < p:
            kept.append(edge)
    return kept


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?# BaselineCalibrator
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
class BaselineCalibrator:
    """Fits and samples from the multivariate distribution of real eBPF data.

    Algorithm:
      1. fit() : compute mean vector 渭, covariance 危, and Cholesky L
         from real observations.  Also record zero-inflation probabilities
         for shell_exec / sensitive_file.
      2. generate_normal() : z ~ N(0,I) 鈫?z_corr = L @ z 鈫?x = 渭 + z_corr * 蟽
         鈫?round counts, clip.
      3. generate_anomaly() : same but then apply DataRecorder._inject_anomaly
         post-hoc.
    """

    def __init__(self, rng_seed: int = 42,
                 num_agents_range: tuple = (4, 16),
                 topology_weights: Optional[dict] = None,
                 causal_strength: float = 1.0):
        self._rng = random.Random(rng_seed)
        self._np_rng = np.random.default_rng(rng_seed)
        self._num_agents_range = num_agents_range
        self._causal_strength = causal_strength

        self._topology_weights = topology_weights or {
            t: 1.0 for t in ALL_TOPOLOGIES
        }

        # fitted parameters
        self._n_int = len(INT_FIELDS)
        self._n_float = len(FLOAT_FIELDS)
        self._n_zero = len(ZERO_INFLATED_FIELDS)
        self._n_fields = len(ALL_FIELDS)
        self._means = None          # [F]
        self._stds = None           # [F]
        self._L = None              # [F, F] Cholesky of correlation
        self._corr = None           # [F, F]

        # zero-inflation probabilities
        self._p_zero_shell = 0.0
        self._p_zero_sensitive = 0.0
        self._shell_pos_mean = 0.0
        self._shell_pos_std = 0.0
        self._sensitive_pos_mean = 0.0
        self._sensitive_pos_std = 0.0

        self._n_real_observations = 0
        self._fitted = False

    # 鈹€鈹€ fitting 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

    def fit(self, observations):
        """Fit multivariate distribution from a list of observation dicts."""
        data = _to_field_array(observations, filter_zero=True)
        if data.shape[0] < 10:
            raise ValueError(
                f"Need 鈮?0 agent-samples (got {data.shape[0]}). "
                "Collect more observations."
            )

        self._means = data.mean(axis=0)
        self._stds = data.std(axis=0)
        self._stds = np.where(self._stds < 1e-8, 1e-8, self._stds)

        self._corr = np.corrcoef(data.T)
        self._corr = np.nan_to_num(self._corr, nan=0.0)
        for jitter_scale in [1e-6, 1e-4, 1e-2]:
            try:
                jitter = np.eye(self._n_fields) * jitter_scale
                self._L = np.linalg.cholesky(self._corr + jitter)
                break
            except np.linalg.LinAlgError:
                continue
        else:
            self._L = np.eye(self._n_fields)

        # zero-inflation for shell_exec_count / sensitive_file_count
        shell_col = data[:, self._field_index("shell_exec_count")]
        self._p_zero_shell = float((shell_col == 0).mean())
        pos_vals = shell_col[shell_col > 0]
        if len(pos_vals) > 0:
            self._shell_pos_mean = float(pos_vals.mean())
            self._shell_pos_std = float(max(pos_vals.std(), 0.5))

        sensitive_col = data[:, self._field_index("sensitive_file_count")]
        self._p_zero_sensitive = float((sensitive_col == 0).mean())
        pos_vals2 = sensitive_col[sensitive_col > 0]
        if len(pos_vals2) > 0:
            self._sensitive_pos_mean = float(pos_vals2.mean())
            self._sensitive_pos_std = float(max(pos_vals2.std(), 0.5))

        self._n_real_observations = len(observations)
        self._fitted = True
        logger.info(
            "Calibrator fitted: %d agent-samples, %d fields, "
            "shell_zero=%.2f, sensitive_zero=%.2f",
            data.shape[0], self._n_fields,
            self._p_zero_shell, self._p_zero_sensitive,
        )
        return self

    # 鈹€鈹€ field ordering 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

    def _field_index(self, name: str) -> int:
        return ALL_FIELDS.index(name)

    # 鈹€鈹€ core sampling 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

    def _sample_fields(self):
        """Sample one row of [F] field values preserving covariance."""
        if not self._fitted:
            raise RuntimeError("call fit() first")
        z = self._np_rng.normal(size=self._n_fields)
        z_corr = self._L @ z
        x_raw = self._means + z_corr * self._stds

        result = {}
        for i, f in enumerate(ALL_FIELDS):
            result[f] = _clip_generated(x_raw[i], i, self._n_int)

        # zero-inflation correction
        if self._rng.random() < self._p_zero_shell:
            result["shell_exec_count"] = 0
        if self._rng.random() < self._p_zero_sensitive:
            result["sensitive_file_count"] = 0

        return result

    def _pick_num_agents(self):
        low, high = self._num_agents_range
        return self._rng.randint(low, high)

    def _pick_topology(self):
        items = list(self._topology_weights.items())
        topos, weights = zip(*items)
        return self._rng.choices(topos, weights=weights, k=1)[0]

    def _make_agent_ids(self, n):
        return [f"agent_{i}" for i in range(n)]

    # 鈹€鈹€ interaction graph builders 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

    def _build_interactions(self, topology: str, agent_ids, rng, fields_list=None):
        """Build interaction list for the given topology.

        If causal_strength > 0 and fields_list is provided, edges are
        filtered by a logistic model based on agent metrics.
        """
        n = len(agent_ids)
        if n < 2:
            return []

        ts = rng.randint(0, 1000000) * 30_000_000_000
        builder = TOPOLOGY_BUILDERS.get(topology)
        if builder is None:
            builder = TOPOLOGY_BUILDERS["random"]

        interactions = builder(agent_ids, rng, metrics_dict=fields_list)

        # Apply causal edge filtering
        if self._causal_strength > 0 and fields_list:
            interactions = _apply_causal_edges(
                interactions, agent_ids, fields_list, rng, self._causal_strength
            )

        for e in interactions:
            e["timestamp_ns"] = ts
        return interactions

    def _build_step(self, fields_list, topology: str, agent_ids, base_seed: int):
        """Assemble one complete observation dict.

        fields_list: list of dicts, one per agent (from _sample_fields).
        """
        rng = random.Random(base_seed)
        ts = rng.randint(0, 1000000) * 30_000_000_000

        agents = {}
        for i, aid in enumerate(agent_ids):
            agents[aid] = fields_list[i]

        interactions = self._build_interactions(topology, agent_ids, rng, fields_list)

        return {
            "agents": agents,
            "interactions": interactions,
            "messages": [],
            "anomalies": [],
            "timestamp": ts,
            "window_start_ns": ts - 30_000_000_000,
            "label": 0,
            "_anomaly_target": None,
            "_anomaly_type": None,
            "_num_agents": len(agent_ids),
            "_topology": topology,
        }

    # 鈹€鈹€ public generators 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

    def generate_normal(self, topology: Optional[str] = None,
                        num: int = 100) -> list:
        """Generate normal observations preserving real-data covariance.

        When topology is None, each observation picks a random topology
        and random agent count from the configured range.
        """
        if not self._fitted:
            raise RuntimeError("call fit() first")

        result = []
        for i in range(num):
            t = topology if topology else self._pick_topology()
            n = len(self._make_agent_ids(self._pick_num_agents())) if self._num_agents_range else 4
            agent_ids = self._make_agent_ids(n)
            fields = [self._sample_fields() for _ in agent_ids]
            obs = self._build_step(fields, t, agent_ids, i * 7 + 42)
            obs["label"] = 0
            result.append(obs)

        logger.info("Generated %d normal observations (var agent/topo)", num)
        return result

    _ANOMALY_TYPES_DEFAULT = [
        "resource", "security", "logic_loop", "message_surge",
        "collusion", "topology_anomaly",
        "stale_state", "seq_violation", "ignore_peer",
        "contradict_action", "overlap_write", "context_drop",
    ]

    def generate_anomaly(self, topology: Optional[str] = None,
                         num: int = 50,
                         anomaly_types: Optional[list] = None,
                         severity: str = "severe") -> list:
        """Generate anomalous observations.

        severity controls injection magnitude:
          - "subtle":   0.1-0.5x baseline variance
          - "moderate": 1-2x
          - "severe":   3-20x (original default)
        """
        if not self._fitted:
            raise RuntimeError("call fit() first")
        if anomaly_types is None:
            anomaly_types = self._ANOMALY_TYPES_DEFAULT

        result = []
        for i in range(num):
            t = topology if topology else self._pick_topology()
            n = self._pick_num_agents()
            agent_ids = self._make_agent_ids(n)
            fields = [self._sample_fields() for _ in agent_ids]
            obs = self._build_step(fields, t, agent_ids, i * 13 + 42)

            target = self._rng.choice(agent_ids)
            anom_type = self._rng.choice(anomaly_types)

            if anom_type in ("collusion",):
                # collusion: 2 agents get moderate anomalies simultaneously
                others = [a for a in agent_ids if a != target]
                if others:
                    target2 = self._rng.choice(others)
                    DataRecorder._inject_anomaly(
                        obs, target, "resource", self._rng, severity="moderate"
                    )
                    DataRecorder._inject_anomaly(
                        obs, target2, "logic_loop", self._rng, severity="moderate"
                    )
                    obs["_anomaly_target"] = f"{target},{target2}"
                    obs["_anomaly_type"] = "collusion"
                else:
                    DataRecorder._inject_anomaly(
                        obs, target, anom_type, self._rng, severity=severity
                    )

            elif anom_type == "topology_anomaly":
                # Rewire: remove all target's existing edges, connect to
                # new partners with feature-level side effects.
                others = [a for a in agent_ids if a != target]
                if others:
                    # 1. Find target's current interaction partners
                    existing_edges = [
                        e for e in obs["interactions"]
                        if e["src"] == target or e["dst"] == target
                    ]
                    existing_partners = set()
                    for e in existing_edges:
                        existing_partners.add(e["src"] if e["dst"] == target else e["dst"])

                    # 2. Remove all existing interactions involving target
                    obs["interactions"] = [
                        e for e in obs["interactions"]
                        if e["src"] != target and e["dst"] != target
                    ]

                    # 3. Pick new partners (different from existing)
                    candidates = [a for a in others if a not in existing_partners]
                    if not candidates:
                        candidates = others
                    n_new = max(1, min(len(candidates),
                                       max(2, len(existing_partners) // 2)))
                    new_partners = self._rng.sample(candidates, n_new)

                    # 4. Add bidirectional edges to new partners
                    for partner in new_partners:
                        weight = round(self._rng.uniform(0.5, 1.0), 3)
                        obs["interactions"].append({
                            "src": target, "dst": partner,
                            "type": "api_call",
                            "weight": weight,
                            "timestamp_ns": obs["timestamp"],
                        })
                        obs["interactions"].append({
                            "src": partner, "dst": target,
                            "type": "api_call",
                            "weight": weight,
                            "timestamp_ns": obs["timestamp"],
                        })

                    # 5. Feature-level side effects on target agent
                    agent = obs["agents"].get(target)
                    if agent:
                        agent["api_call_count"] = (
                            int(agent.get("api_call_count", 0))
                            + int(self._rng.randint(5, 20))
                        )
                        agent["msg_sent"] = (
                            int(agent.get("msg_sent", 0))
                            + int(self._rng.randint(3, 15))
                        )
                        agent["msg_received"] = (
                            int(agent.get("msg_received", 0))
                            + int(self._rng.randint(3, 15))
                        )

                    obs["label"] = 1
                    obs["_anomaly_target"] = f"{target}↔{','.join(new_partners)}"
                    obs["_anomaly_type"] = "topology_anomaly"
                else:
                    DataRecorder._inject_anomaly(
                        obs, target, "resource", self._rng, severity=severity
                    )

            else:
                DataRecorder._inject_anomaly(
                    obs, target, anom_type, self._rng, severity=severity
                )
                obs["_anomaly_type"] = anom_type

            result.append(obs)

        logger.info("Generated %d anomaly observations (severity=%s, types=%s)",
                     num, severity, anomaly_types)
        return result

    # 鈹€鈹€ dataset export 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

    def generate_dataset(self, topology: Optional[str] = None,
                         num_normal: int = 500, num_anomaly: int = 100,
                         output_dir: str = "training_data",
                         val_split: float = 0.12, test_split: float = 0.18,
                         anomaly_severity: str = "severe",
                         ) -> dict:
        """Generate and save a full dataset for training."""
        os.makedirs(output_dir, exist_ok=True)

        normal = self.generate_normal(topology=topology, num=num_normal)
        anomaly = self.generate_anomaly(
            topology=topology, num=num_anomaly, severity=anomaly_severity,
        )

        n = normal
        a = anomaly
        rng = self._rng
        rng.shuffle(n)
        rng.shuffle(a)

        n_val = max(1, int(len(n) * val_split))
        n_test = max(1, int(len(n) * test_split))
        n_train = len(n) - n_val - n_test

        n_train_obs = n[:n_train]
        n_val_obs = n[n_train:n_train + n_val]
        n_test_obs = n[n_train + n_val:]

        a_train = a[:max(0, min(len(a), int(len(a) * 0.3)))]
        a_val = a[len(a_train):len(a_train) + max(0, min(len(a), int(len(a) * 0.15)))]
        a_test = a[len(a_train) + len(a_val):]

        def _shuffle(lst):
            rng.shuffle(lst)
            return lst

        def _save(path, data_list):
            with open(path, "w") as f:
                json.dump(data_list, f, indent=2, default=str)
            logger.info("  wrote %s (%d records)", path, len(data_list))

        _save(os.path.join(output_dir, "train_unlabeled.json"),
              n_train_obs)
        _save(os.path.join(output_dir, "train_labeled.json"),
              _shuffle(n_train_obs + a_train))
        _save(os.path.join(output_dir, "val_labeled.json"),
              _shuffle(n_val_obs + a_val))
        _save(os.path.join(output_dir, "test_labeled.json"),
              _shuffle(n_test_obs + a_test))

        meta = {
            "num_agents": "dynamic",
            "topology": topology or "dynamic",
            "source": "baseline_calibrator",
            "calibrated_from": f"{self._n_real_observations} real obs",
            "train_unlabeled": len(n_train_obs),
            "train_labeled": len(n_train_obs) + len(a_train),
            "val_labeled": len(n_val_obs) + len(a_val),
            "test_labeled": len(n_test_obs) + len(a_test),
        }
        _save(os.path.join(output_dir, "meta.json"), meta)
        logger.info("Dataset complete: %s", meta)
        return meta


# 鈹€鈹€ CLI 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Calibrate from real eBPF data and generate training set"
    )
    parser.add_argument("--input", required=True,
                        help="Input .jsonl file(s) from DataRecorder (comma-sep or glob)")
    parser.add_argument("--output-dir", default="training_data",
                        help="Output directory for JSON splits")
    parser.add_argument("--topology", choices=ALL_TOPOLOGIES + [None],
                        default=None, help="Fixed topology (default: random per obs)")
    parser.add_argument("--num-normal", type=int, default=500)
    parser.add_argument("--num-anomaly", type=int, default=100)
    parser.add_argument("--num-agents-min", type=int, default=4)
    parser.add_argument("--num-agents-max", type=int, default=16)
    parser.add_argument("--causal-strength", type=float, default=1.0,
                        help="Causal edge strength (0=topology only, 1=balanced, 2=strong)")
    parser.add_argument("--anomaly-severity", choices=["subtle", "moderate", "severe"],
                        default="severe")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[CALIB] %(message)s")

    import glob
    paths = []
    for part in args.input.split(","):
        paths.extend(sorted(glob.glob(part.strip())))
    if not paths:
        raise FileNotFoundError(f"no files match: {args.input}")

    all_obs = []
    for fp in paths:
        obs = DataRecorder.load_jsonl(fp)
        logger.info("Loaded %d from %s", len(obs), fp)
        all_obs.extend(obs)

    cal = BaselineCalibrator(
        num_agents_range=(args.num_agents_min, args.num_agents_max),
        causal_strength=args.causal_strength,
    )
    cal.fit(all_obs)
    cal.generate_dataset(
        topology=args.topology,
        num_normal=args.num_normal,
        num_anomaly=args.num_anomaly,
        output_dir=args.output_dir,
        anomaly_severity=args.anomaly_severity,
    )


if __name__ == "__main__":
    main()
