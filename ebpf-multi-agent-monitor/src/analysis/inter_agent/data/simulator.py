"""Simulator for generating training data matching the Redis JSON schema.

Generates normal observations and injected anomalies for unsupervised
DOMINANT pre-training and semi-supervised fine-tuning.

Output: JSON files compatible with RedisCollector.get_observation() format.
"""

import base64
import json
import os
import numpy as np
from typing import Optional


class Simulator:
    """Generates synthetic multi-agent observations for GNN training.

    Normal data: metrics sampled from Gaussian/Poisson baselines.
    Anomaly injection: 5 types matching intra_agent detection patterns.

    Usage:
        sim = Simulator(num_agents=4)
        normal = sim.generate_normal()
        sim.inject_resource_anomaly(normal, "agent_0")
        sim.save_dataset("training_data/", num_normal=500, num_anomaly=100)
    """

    AGENT_IDS = ["agent_0", "agent_1", "agent_2", "agent_3"]

    # Baseline distributions for normal operation (from intra_agent baselines)
    BASELINE = {
        "cpu_usage": {"dist": "gaussian", "mu": 0.30, "sigma": 0.10, "clip": (0.0, 0.6)},
        "memory_usage": {"dist": "gaussian", "mu": 0.35, "sigma": 0.10, "clip": (0.0, 0.6)},
        "api_call_count": {"dist": "poisson", "lam": 10, "clip": (0, 40)},
        "msg_sent": {"dist": "poisson", "lam": 5, "clip": (0, 20)},
        "msg_received": {"dist": "poisson", "lam": 5, "clip": (0, 20)},
        "proc_exec_count": {"dist": "poisson", "lam": 2, "clip": (0, 10)},
        "proc_fork_count": {"dist": "poisson", "lam": 1, "clip": (0, 5)},
        "fs_open_count": {"dist": "poisson", "lam": 8, "clip": (0, 30)},
        "fs_read_count": {"dist": "poisson", "lam": 30, "clip": (0, 100)},
        "fs_write_count": {"dist": "poisson", "lam": 15, "clip": (0, 60)},
        "fs_unlink_count": {"dist": "poisson", "lam": 1, "clip": (0, 5)},
        "net_connect_count": {"dist": "poisson", "lam": 10, "clip": (0, 40)},
        "net_send_count": {"dist": "poisson", "lam": 50, "clip": (0, 200)},
        "net_recv_count": {"dist": "poisson", "lam": 45, "clip": (0, 180)},
        "shell_exec_count": 0,         # always 0 in normal
        "sensitive_file_count": 0,     # always 0 in normal
        "unique_files_count": {"dist": "poisson", "lam": 6, "clip": (1, 15)},
    }

    # Edge interaction probabilities (sparse: not all agents talk to all)
    EDGE_PROB = 0.4

    def __init__(self, num_agents: int = 4, seed: Optional[int] = None):
        self.num_agents = num_agents
        self.agent_ids = self.AGENT_IDS[:num_agents]
        self._rng = np.random.default_rng(seed)
        self._step = 0

    # ---- sample helpers ----

    def _sample(self, spec):
        if isinstance(spec, (int, float)):
            return spec
        dist = spec["dist"]
        if dist == "gaussian":
            v = self._rng.normal(spec["mu"], spec["sigma"])
        elif dist == "poisson":
            v = self._rng.poisson(spec["lam"])
        else:
            v = spec.get("mu", 0)
        lo, hi = spec.get("clip", (-np.inf, np.inf))
        return float(np.clip(v, lo, hi))

    def _make_metric(self):
        return {k: int(round(self._sample(v))) if not isinstance(v, (int, float)) else v
                for k, v in self.BASELINE.items()}

    # ---- normal generation ----

    def generate_normal(self) -> dict:
        """Generate one observation window with normal behavior."""
        self._step += 1
        ts = self._step * 30_000_000_000

        agents = {}
        for aid in self.agent_ids:
            agents[aid] = self._make_metric()

        interactions = []
        for i in range(len(self.agent_ids)):
            for j in range(len(self.agent_ids)):
                if i != j and self._rng.random() < self.EDGE_PROB:
                    weight = float(self._rng.uniform(0.1, 0.6))
                    interactions.append({
                        "src": self.agent_ids[i],
                        "dst": self.agent_ids[j],
                        "type": self._rng.choice(["api_call", "message", "file_share"]),
                        "weight": round(weight, 3),
                        "timestamp_ns": ts,
                    })

        messages = []
        for idx, it in enumerate(interactions):
            if self._rng.random() < 0.5:
                payload = f"agent_{it['src']}_to_{it['dst']}_msg_{self._step}_{idx}"
                messages.append({
                    "src": it["src"], "dst": it["dst"],
                    "msg_type": self._rng.choice(["request", "response"]),
                    "data_size": len(payload),
                    "timestamp_ns": ts,
                    "data": base64.b64encode(payload.encode()).decode(),
                })

        return {
            "agents": agents,
            "interactions": interactions,
            "messages": messages,
            "anomalies": [],
            "timestamp": ts,
            "window_start_ns": ts - 30_000_000_000,
            "label": 0,
            "_anomaly_target": None,
        }

    # ---- anomaly injection (in-place) ----

    def inject_resource_anomaly(self, obs: dict, target: str):
        """CPU/memory exceed thresholds (intra_agent RESOURCE pattern)."""
        if target not in obs["agents"]:
            return
        obs["agents"][target]["cpu_usage"] = round(float(self._rng.uniform(0.85, 0.98)), 3)
        obs["agents"][target]["memory_usage"] = round(float(self._rng.uniform(0.80, 0.95)), 3)
        obs["label"] = 1
        obs["_anomaly_target"] = target

    def inject_security_anomaly(self, obs: dict, target: str):
        """Shell exec + sensitive file access (intra_agent SECURITY pattern)."""
        if target not in obs["agents"]:
            return
        obs["agents"][target]["shell_exec_count"] = int(self._rng.integers(1, 3))
        obs["agents"][target]["sensitive_file_count"] = int(self._rng.integers(1, 3))
        obs["anomalies"].append({
            "agent_id": target,
            "rule": "UNEXPECTED_SHELL_EXEC",
            "severity": "HIGH", "risk_score": 0.9,
            "description": "Shell exec detected",
            "timestamp_ns": obs["timestamp"],
        })
        obs["label"] = 1
        obs["_anomaly_target"] = target

    def inject_logic_loop(self, obs: dict, target: str):
        """High IO + few unique files (intra_agent LOGIC_LOOP pattern)."""
        if target not in obs["agents"]:
            return
        obs["agents"][target]["fs_read_count"] = int(self._rng.poisson(200))
        obs["agents"][target]["fs_write_count"] = int(self._rng.poisson(180))
        obs["agents"][target]["unique_files_count"] = int(self._rng.integers(1, 3))
        obs["anomalies"].append({
            "agent_id": target,
            "rule": "POSSIBLE_LOGIC_LOOP",
            "severity": "MEDIUM", "risk_score": 0.6,
            "description": "High IO with few files",
            "timestamp_ns": obs["timestamp"],
        })
        obs["label"] = 1
        obs["_anomaly_target"] = target

    def inject_message_anomaly(self, obs: dict, target: str):
        """Message frequency surge / cascade storm."""
        for aid in self.agent_ids:
            if aid != target:
                for _ in range(int(self._rng.integers(5, 15))):
                    obs["messages"].append({
                        "src": aid, "dst": target,
                        "msg_type": "request",
                        "data_size": int(self._rng.integers(100, 8000)),
                        "timestamp_ns": obs["timestamp"],
                    })
                obs["interactions"].append({
                    "src": aid, "dst": target,
                    "type": "message", "weight": round(float(self._rng.uniform(0.7, 0.95)), 3),
                    "timestamp_ns": obs["timestamp"],
                })
        obs["agents"][target]["msg_received"] += int(self._rng.integers(20, 50))
        obs["label"] = 1
        obs["_anomaly_target"] = target

    def inject_propagation_anomaly(self, obs: dict, start_agent: str):
        """Propagation chain across multiple agents."""
        n = len(self.agent_ids)
        idx = self.agent_ids.index(start_agent)
        for i in range(1, n):
            src = self.agent_ids[(idx + i - 1) % n]
            dst = self.agent_ids[(idx + i) % n]
            obs["interactions"].append({
                "src": src, "dst": dst,
                "type": "api_call", "weight": round(float(self._rng.uniform(0.6, 0.9)), 3),
                "timestamp_ns": obs["timestamp"],
            })
            obs["agents"][dst]["api_call_count"] += int(self._rng.integers(30, 60))
        obs["agents"][start_agent]["cpu_usage"] = round(float(self._rng.uniform(0.80, 0.90)), 3)
        obs["label"] = 1
        obs["_anomaly_target"] = self.agent_ids[:]

    def inject_context_drop(self, obs: dict, target: str):
        """Agent repeats identical messages (context window loss)."""
        if target not in obs["agents"]:
            return
        repeated_payload = base64.b64encode(
            f"REPEATED_{target}_msg".encode()
        ).decode()
        for msg in obs.get("messages", []):
            if msg["src"] == target:
                msg["data"] = repeated_payload
                msg["data_size"] = len(repeated_payload)
        obs["anomalies"].append({
            "agent_id": target,
            "rule": "CONTEXT_DROP",
            "severity": "HIGH", "risk_score": 0.8,
            "description": "Repeated identical messages (context loss)",
            "timestamp_ns": obs["timestamp"],
        })
        obs["label"] = 1
        obs["_anomaly_target"] = target

    def inject_contradict_action(self, obs: dict, target: str):
        """Agent sends contradictory messages (e.g. open then close same file)."""
        if target not in obs["agents"]:
            return
        target_msgs = [m for m in obs.get("messages", []) if m["src"] == target]
        for i, msg in enumerate(target_msgs):
            if i % 2 == 0:
                payload = f"OPEN_FILE_{target}_request"
            else:
                payload = f"CLOSE_FILE_{target}_request"
            msg["data"] = base64.b64encode(payload.encode()).decode()
            msg["data_size"] = len(payload)
        obs["anomalies"].append({
            "agent_id": target,
            "rule": "CONTRADICT_ACTION",
            "severity": "MEDIUM", "risk_score": 0.7,
            "description": "Contradictory action sequence detected",
            "timestamp_ns": obs["timestamp"],
        })
        obs["label"] = 1
        obs["_anomaly_target"] = target

    def inject_ignore_peer(self, obs: dict, target: str):
        """Agent ignores messages from a specific peer."""
        if target not in obs["agents"]:
            return
        peers = [a for a in self.agent_ids if a != target]
        if not peers:
            return
        ignored_peer = self._rng.choice(peers)
        obs["interactions"] = [
            it for it in obs.get("interactions", [])
            if not (it["src"] == ignored_peer and it["dst"] == target)
        ]
        obs["messages"] = [
            m for m in obs.get("messages", [])
            if not (m["src"] == ignored_peer and m["dst"] == target)
        ]
        obs["agents"][target]["msg_received"] = max(
            0, obs["agents"][target].get("msg_received", 0) - self._rng.integers(2, 6)
        )
        obs["anomalies"].append({
            "agent_id": target,
            "rule": "IGNORE_PEER",
            "severity": "MEDIUM", "risk_score": 0.6,
            "description": f"Ignoring messages from {ignored_peer}",
            "timestamp_ns": obs["timestamp"],
        })
        obs["label"] = 1
        obs["_anomaly_target"] = target

    # ---- dataset generation ----

    def generate_dataset(self, num_normal: int = 500, num_anomaly: int = 100,
                         output_dir: str = "training_data") -> dict:
        """Generate and save train/val/test splits as JSON files.

        Returns split metadata dict with counts.
        """
        os.makedirs(output_dir, exist_ok=True)

        anomaly_types = [
            self.inject_resource_anomaly,
            self.inject_security_anomaly,
            self.inject_logic_loop,
            self.inject_message_anomaly,
            self.inject_propagation_anomaly,
            self.inject_context_drop,
            self.inject_contradict_action,
            self.inject_ignore_peer,
        ]

        normal_data = [self.generate_normal() for _ in range(num_normal)]
        anomaly_data = []
        targets = self.agent_ids
        for _ in range(num_anomaly):
            obs = self.generate_normal()
            atype = self._rng.integers(0, len(anomaly_types))
            target = targets[self._rng.integers(0, len(targets))]
            anomaly_types[atype](obs, target)
            obs["_anomaly_type"] = atype
            anomaly_data.append(obs)

        self._rng.shuffle(normal_data)
        self._rng.shuffle(anomaly_data)

        # Compute split indices dynamically from actual counts.
        # Ratios: normal -> 70/15/15, anomaly -> 50/20/30 (test gets remainder).
        n_train_normal = int(num_normal * 0.70)
        n_val_normal   = int(num_normal * 0.15)
        n_train_anom   = int(num_anomaly * 0.50)
        n_val_anom     = int(num_anomaly * 0.20)

        splits = {
            "train": {
                "normal": normal_data[:n_train_normal],
                "anomaly": anomaly_data[:n_train_anom],
            },
            "val": {
                "normal": normal_data[n_train_normal:n_train_normal + n_val_normal],
                "anomaly": anomaly_data[n_train_anom:n_train_anom + n_val_anom],
            },
            "test": {
                "normal": normal_data[n_train_normal + n_val_normal:],
                "anomaly": anomaly_data[n_train_anom + n_val_anom:],
            },
        }

        # Unlabeled: normal only (for DOMINANT pre-training)
        unlabeled = splits["train"]["normal"]
        self._save_json(os.path.join(output_dir, "train_unlabeled.json"), unlabeled)

        # Labeled: normal + anomaly (for fine-tuning)
        for split_name, split_data in splits.items():
            combined = split_data["normal"] + split_data["anomaly"]
            self._rng.shuffle(combined)
            self._save_json(os.path.join(output_dir, f"{split_name}_labeled.json"), combined)

        meta = {
            "num_agents": self.num_agents,
            "agent_ids": self.agent_ids,
            "train_unlabeled": len(splits["train"]["normal"]),
            "train_labeled": len(splits["train"]["normal"]) + len(splits["train"]["anomaly"]),
            "val_labeled": len(splits["val"]["normal"]) + len(splits["val"]["anomaly"]),
            "test_labeled": len(splits["test"]["normal"]) + len(splits["test"]["anomaly"]),
            "anomaly_types": ["resource", "security", "logic", "message", "propagation",
                              "context_drop", "contradict_action", "ignore_peer"],
        }
        self._save_json(os.path.join(output_dir, "meta.json"), meta)
        return meta

    @staticmethod
    def _save_json(path: str, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    @staticmethod
    def load_dataset(data_dir: str = "training_data"):
        """Load pre-generated dataset from JSON files."""
        def load(path):
            with open(path) as f:
                return json.load(f)
        return {
            "train_unlabeled": load(os.path.join(data_dir, "train_unlabeled.json")),
            "train_labeled": load(os.path.join(data_dir, "train_labeled.json")),
            "val_labeled": load(os.path.join(data_dir, "val_labeled.json")),
            "test_labeled": load(os.path.join(data_dir, "test_labeled.json")),
            "meta": load(os.path.join(data_dir, "meta.json")),
        }
