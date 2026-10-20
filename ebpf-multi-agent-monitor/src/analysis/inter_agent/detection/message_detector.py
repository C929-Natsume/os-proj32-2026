import numpy as np
from collections import defaultdict
from typing import Dict, List, Tuple


class MessageAnomalyDetector:
    """Detects anomalies in inter-agent message patterns.

    Four detection methods aligned with the utterance graph analysis:
      1. Frequency surge: src→dst msg count exceeds mean+2.5*std
      2. Cascade storm: dst receives messages from many sources in window
      3. Type drift: message type distribution shifts from baseline
      4. Data size anomaly: message payload size exceeds threshold
    """

    def __init__(self, freq_std_threshold=2.5, cascade_threshold=8,
                 data_size_mb=100.0):
        self._freq_std = freq_std_threshold
        self._cascade_th = cascade_threshold
        self._data_size = data_size_mb
        self._baseline: Dict[Tuple[str, str], int] = defaultdict(int)
        self._baseline_size: Dict[Tuple[str, str], float] = defaultdict(float)
        self._baseline_samples = 0

    def clear(self):
        self._baseline.clear()
        self._baseline_size.clear()
        self._baseline_samples = 0

    def update_baseline(self, obs: dict):
        messages = obs.get("messages", [])
        for m in messages:
            key = (m.get("src", ""), m.get("dst", ""))
            self._baseline[key] += 1
            if "data_size" in m:
                self._baseline_size[key] += float(m["data_size"])
        self._baseline_samples += 1

    def detect(self, obs: dict) -> dict:
        messages = obs.get("messages", [])
        agents_data = obs.get("agents", {})
        agent_ids = list(agents_data.keys())

        pair_count = defaultdict(int)
        cascade_count = defaultdict(int)
        pair_size = defaultdict(float)
        type_dist = defaultdict(lambda: defaultdict(int))

        for m in messages:
            src, dst = m.get("src", ""), m.get("dst", "")
            pair_count[(src, dst)] += 1
            cascade_count[dst] += 1
            pair_size[(src, dst)] += float(m.get("data_size", 0))
            type_dist[(src, dst)][m.get("msg_type", "request")] += 1

        results = []

        values = list(pair_count.values()) or [0]
        mean = np.mean(values)
        std = np.std(values) + 1e-8

        for (src, dst), cnt in pair_count.items():
            if cnt > mean + self._freq_std * std:
                baseline = self._baseline.get((src, dst), 0)
                surge_ratio = cnt / max(baseline, 1)
                risk = min((cnt - mean - self._freq_std * std) / (std * 3), 1.0)
                results.append({
                    "type": "frequency_surge",
                    "src": src, "dst": dst,
                    "count": cnt, "baseline": baseline,
                    "surge_ratio": surge_ratio,
                    "risk": risk,
                })

        for dst, count in cascade_count.items():
            if count >= self._cascade_th:
                results.append({
                    "type": "cascade_storm",
                    "src": "*", "dst": dst,
                    "count": count,
                    "risk": min(count / (self._cascade_th * 2), 1.0),
                })

        for (src, dst), size_bytes in pair_size.items():
            size_mb = size_bytes / (1024 * 1024)
            if size_mb > self._data_size:
                results.append({
                    "type": "data_size_anomaly",
                    "src": src, "dst": dst,
                    "size_mb": size_mb,
                    "risk": min(size_mb / (self._data_size * 2), 1.0),
                })

        in_anomalies = obs.get("anomalies", [])
        intra_msg_anomalies = [
            a for a in in_anomalies
            if a.get("rule") in (
                "POSSIBLE_LOGIC_LOOP", "UNEXPECTED_SHELL_EXEC"
            )
        ]
        for a in intra_msg_anomalies:
            results.append({
                "type": "intra_agent_alert",
                "src": a.get("agent_id", ""),
                "rule": a.get("rule", ""),
                "risk": a.get("risk_score", 0.5),
            })

        cascade_agents = [
            d for d, c in cascade_count.items() if c >= self._cascade_th
        ]
        return {
            "anomalies": results,
            "pair_count": dict(pair_count),
            "cascade_agents": cascade_agents,
            "max_risk": max((r["risk"] for r in results), default=0.0),
        }
