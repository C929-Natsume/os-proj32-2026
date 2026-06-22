import numpy as np
from collections import deque
from typing import Dict, List, Optional

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    nn = None


class TemporalEncoder:
    def __init__(self, input_dim=4, hidden_dim=32, num_layers=2):
        self._input_dim = input_dim
        self._hidden_dim = hidden_dim
        self._dummy = True


class TemporalAnomalyDetector:
    """Temporal anomaly detection across observation windows.

    Maintains a sliding window of agent feature histories and detects
    significant deviations from recent patterns.
    """

    def __init__(self, window_size=10, risk_threshold=0.6):
        self._window_size = window_size
        self._risk_threshold = risk_threshold
        self._history: Dict[str, deque] = {}

    def update(self, obs: dict):
        agents_data = obs.get("agents", {})
        for aid, info in agents_data.items():
            if aid not in self._history:
                self._history[aid] = deque(maxlen=self._window_size)
            feat = np.array([
                float(info.get("cpu_usage", 0)),
                float(info.get("memory_usage", 0)),
                float(info.get("api_call_count", 0)),
                float(info.get("msg_sent", 0)) + float(info.get("msg_received", 0)),
            ], dtype=np.float32)
            self._history[aid].append(feat)

    def detect(self) -> dict:
        scores = {}
        for aid, hist in self._history.items():
            arr = np.array(hist)
            if len(arr) < 3:
                scores[aid] = 0.0
                continue
            mean = np.mean(arr, axis=0)
            std = np.std(arr, axis=0) + 1e-8
            latest = arr[-1]
            z_scores = np.abs((latest - mean) / std)
            risk = float(np.mean(z_scores) / 5.0)
            scores[aid] = min(risk, 1.0)
        return {
            "temporal_scores": scores,
            "anomaly_agents": [
                aid for aid, s in scores.items()
                if s > self._risk_threshold
            ],
        }

    def get_history_size(self, agent_id: str) -> int:
        return len(self._history.get(agent_id, []))

    def clear(self):
        self._history.clear()
