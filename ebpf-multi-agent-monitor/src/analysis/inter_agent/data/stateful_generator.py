"""StatefulGenerator — wraps BaselineCalibrator with temporal dynamics.

Generates sequences of observations where each step depends on the previous
one via a first-order autoregressive process (AR(1)):

    z_t = alpha * z_{t-1} + sqrt(1 - alpha^2) * N(0, I)
    x_t = mu + L @ z_t * std

This preserves the real-data covariance while adding realistic temporal
continuity. Supports gradual-drift and oscillatory anomaly types.

Usage:
    cal = BaselineCalibrator()
    cal.fit(observations)

    gen = StatefulGenerator(cal, alpha=0.8)
    seq = gen.generate_sequence(length=60)
"""

import logging
import math
import random
from typing import Optional

import numpy as np

from inter_agent.data.baseline_calibrator import (
    ALL_FIELDS, INT_FIELDS, FLOAT_FIELDS, ZERO_INFLATED_FIELDS,
    _clip_generated,
)
from inter_agent.data.data_recorder import DataRecorder

logger = logging.getLogger(__name__)


class StatefulGenerator:
    """Generates temporally-correlated observation sequences.

    Each step's field values are autocorrelated with the previous step
    via an AR(1) process on the whitened latent space (z).

    Attributes:
        alpha: temporal autocorrelation coefficient [0, 1).
               0 = independent (same as BaselineCalibrator).
               0.9 = strong temporal smoothness.
    """

    def __init__(self, calibrator, alpha: float = 0.8, rng_seed: int = 42):
        self._cal = calibrator
        assert calibrator._fitted, "calibrator must be fitted"
        self._alpha = alpha
        self._rng = random.Random(rng_seed)
        self._np_rng = np.random.default_rng(rng_seed)
        self._prev_z = None  # previous whitened latent vector

    def reset(self):
        """Reset temporal state (start a fresh sequence)."""
        self._prev_z = None

    def step(self, agent_ids):
        """Generate one observation, temporally dependent on previous step.

        Returns:
            dict: observation with agents, interactions, etc.
        """
        n = len(agent_ids)
        fields = []
        for _ in range(n):
            z = self._np_rng.normal(size=self._cal._n_fields)
            if self._prev_z is not None:
                z = self._alpha * self._prev_z + math.sqrt(1 - self._alpha ** 2) * z
            self._prev_z = z.copy()

            z_corr = self._cal._L @ z
            x_raw = self._cal._means + z_corr * self._cal._stds

            result = {}
            for i, f in enumerate(ALL_FIELDS):
                result[f] = _clip_generated(x_raw[i], i, self._cal._n_int)

            if self._rng.random() < self._cal._p_zero_shell:
                result["shell_exec_count"] = 0
            if self._rng.random() < self._cal._p_zero_sensitive:
                result["sensitive_file_count"] = 0

            fields.append(result)

        return fields

    def generate_sequence(self, length: int, num_agents: int = 4,
                          topology: str = "hierarchical",
                          anomaly_injections: Optional[list] = None,
                          base_seed: int = 42):
        """Generate a temporally-correlated observation sequence.

        Args:
            length: number of time steps.
            num_agents: fixed agent count for the sequence.
            topology: interaction topology.
            anomaly_injections: list of (step_index, target, type, severity)
                                to inject at specific time steps.

        Returns:
            list of observation dicts.
        """
        from inter_agent.data.baseline_calibrator import BaselineCalibrator
        self.reset()
        agent_ids = [f"agent_{i}" for i in range(num_agents)]
        anomaly_injections = anomaly_injections or []

        seq = []
        for t in range(length):
            rng = random.Random(base_seed + t * 17)
            fields = self.step(agent_ids)

            obs = {
                "agents": {aid: f for aid, f in zip(agent_ids, fields)},
                "interactions": [],
                "messages": [],
                "anomalies": [],
                "timestamp": t * 30_000_000_000,
                "window_start_ns": (t - 1) * 30_000_000_000 if t > 0 else 0,
                "label": 0,
                "_anomaly_target": None,
                "_anomaly_type": None,
                "_step": t,
                "_num_agents": num_agents,
                "_topology": topology,
            }

            # Build interactions via calibrator
            obs["interactions"] = self._cal._build_interactions(
                topology, agent_ids, rng, fields
            )

            # Apply scheduled anomaly injections
            for step_idx, target, anom_type, severity in anomaly_injections:
                if step_idx == t:
                    if anom_type == "gradual_drift":
                        # Drift magnitude increases with distance from onset
                        drift_onset = step_idx
                        drift_strength = (t - drift_onset + 1) / length
                        _inject_gradual_drift(obs, target, drift_strength, rng)
                    elif anom_type == "oscillation":
                        _inject_oscillation(obs, target, t, rng)
                    else:
                        DataRecorder._inject_anomaly(
                            obs, target, anom_type, rng, severity=severity
                        )

            seq.append(obs)

        logger.info("Generated %d-step sequence (alpha=%.2f, topo=%s, %d agents)",
                     length, self._alpha, topology, num_agents)
        return seq

    def generate_mixed_dataset(self, seq_lengths: Optional[list] = None,
                               topology: str = "hierarchical",
                               num_agents_range: tuple = (4, 8),
                               num_normal_seq: int = 10,
                               num_anomaly_seq: int = 5,
                               output_dir: str = "training_data_temporal",
                               val_split: float = 0.12,
                               test_split: float = 0.18):
        """Generate a full temporal dataset with mixed-length sequences."""
        import os, json
        os.makedirs(output_dir, exist_ok=True)

        seq_lengths = seq_lengths or [20, 30, 40, 50, 60]

        all_normal = []
        for _ in range(num_normal_seq):
            length = self._rng.choice(seq_lengths)
            n_agents = self._rng.randint(*num_agents_range)
            topo = self._rng.choice([
                "hierarchical", "chain", "tree", "ring", "peer-to-peer",
            ])
            seq = self.generate_sequence(
                length=length, num_agents=n_agents, topology=topo,
            )
            all_normal.extend(seq)

        all_anomaly = []
        for _ in range(num_anomaly_seq):
            length = self._rng.choice(seq_lengths)
            n_agents = self._rng.randint(*num_agents_range)
            topo = self._rng.choice([
                "hierarchical", "chain", "tree", "ring", "peer-to-peer",
            ])
            anomaly_types_pool = [
                "resource", "security", "logic_loop", "message_surge",
                "gradual_drift", "oscillation",
                "stale_state", "seq_violation", "ignore_peer",
                "contradict_action", "overlap_write", "context_drop",
            ]
            injections = []
            for anomaly_step in range(10, length, self._rng.randint(5, 15)):
                target = f"agent_{self._rng.randint(0, n_agents - 1)}"
                at = self._rng.choice(anomaly_types_pool)
                sev = self._rng.choices(
                    ["subtle", "moderate", "severe"], weights=[0.4, 0.3, 0.3], k=1
                )[0]
                injections.append((anomaly_step, target, at, sev))
            seq = self.generate_sequence(
                length=length, num_agents=n_agents, topology=topo,
                anomaly_injections=injections,
            )
            all_anomaly.extend(seq)

        rng = self._rng
        rng.shuffle(all_normal)
        rng.shuffle(all_anomaly)

        n_val = max(1, int(len(all_normal) * val_split))
        n_test = max(1, int(len(all_normal) * test_split))
        n_train = len(all_normal) - n_val - n_test

        def _shuffle(lst):
            rng.shuffle(lst)
            return lst

        def _save(path, data_list):
            with open(path, "w") as f:
                json.dump(data_list, f, indent=2, default=str)
            logger.info("  wrote %s (%d records)", path, len(data_list))

        _save(os.path.join(output_dir, "train_unlabeled.json"), all_normal[:n_train])
        _save(os.path.join(output_dir, "train_labeled.json"),
              _shuffle(all_normal[:n_train] + all_anomaly[:max(1, len(all_anomaly)//3)]))
        _save(os.path.join(output_dir, "val_labeled.json"),
              _shuffle(all_normal[n_train:n_train + n_val] +
                       all_anomaly[max(1, len(all_anomaly)//3):max(1, len(all_anomaly)//3) + max(1, len(all_anomaly)//6)]))
        _save(os.path.join(output_dir, "test_labeled.json"),
              _shuffle(all_normal[n_train + n_val:] + all_anomaly[len(all_anomaly)//3 + len(all_anomaly)//6:]))

        meta = {
            "source": "stateful_generator",
            "alpha": self._alpha,
            "num_normal_seq": num_normal_seq,
            "num_anomaly_seq": num_anomaly_seq,
            "train_unlabeled": len(all_normal[:n_train]),
            "train_labeled": len(all_normal[:n_train]) + len(all_anomaly[:max(1, len(all_anomaly)//3)]),
            "val_labeled": len(all_normal[n_train:n_train + n_val]) + len(all_anomaly[max(1, len(all_anomaly)//3):max(1, len(all_anomaly)//3) + max(1, len(all_anomaly)//6)]),
            "test_labeled": len(all_normal[n_train + n_val:]) + len(all_anomaly[len(all_anomaly)//3 + len(all_anomaly)//6:]),
        }
        _save(os.path.join(output_dir, "meta.json"), meta)
        logger.info("Temporal dataset complete: %s", meta)
        return meta


def _inject_gradual_drift(obs, target, strength, rng):
    """Drift anomaly: increase CPU, mem, fork progressively over steps."""
    agent = obs["agents"].get(target)
    if not agent:
        return
    factor = 1.0 + strength * 3.0
    agent["cpu_usage"] = round(min(float(agent.get("cpu_usage", 0)) * factor, 0.99), 3)
    agent["memory_usage"] = round(min(float(agent.get("memory_usage", 0)) * factor, 0.95), 3)
    agent["proc_fork_count"] = int(agent.get("proc_fork_count", 0)) + int(strength * 10)
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "gradual_drift"
    obs.setdefault("anomalies", []).append({
        "agent_id": target, "rule": "GRADUAL_DRIFT",
        "severity": "MEDIUM",
        "risk_score": round(min(strength, 1.0), 3),
        "description": f"Gradual drift: CPU={agent['cpu_usage']} (strength={strength:.2f})",
        "timestamp_ns": obs.get("timestamp", 0),
    })


def _inject_oscillation(obs, target, step, rng):
    """Oscillation anomaly: sinusoidal pattern on IO fields."""
    agent = obs["agents"].get(target)
    if not agent:
        return
    amplitude = 0.5 + 0.5 * math.sin(step * 0.5)
    agent["fs_read_count"] = int(agent.get("fs_read_count", 0)) + int(amplitude * 100)
    agent["fs_write_count"] = int(agent.get("fs_write_count", 0)) + int(amplitude * 80)
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "oscillation"
    obs.setdefault("anomalies", []).append({
        "agent_id": target, "rule": "OSCILLATION",
        "severity": "LOW",
        "risk_score": round(amplitude * 0.5, 3),
        "description": f"Oscillatory IO: read+write={agent['fs_read_count'] + agent['fs_write_count']}",
        "timestamp_ns": obs.get("timestamp", 0),
    })
