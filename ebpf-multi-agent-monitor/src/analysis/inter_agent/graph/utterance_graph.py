from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class UtteranceRecord:
    def __init__(self, src, dst, msg_type, data_size, timestamp_ns):
        self.src = src
        self.dst = dst
        self.msg_type = msg_type
        self.data_size = data_size
        self.timestamp_ns = timestamp_ns


class UtteranceGraph:
    """Tracks inter-agent message patterns (utterance graph per G-Safeguard).

    Maintains message frequency, type distribution, and cascade detection
    counts per agent pair, derived from Redis inter:messages stream.
    """

    def __init__(self):
        self._messages: List[UtteranceRecord] = []
        self._src_dst_count: Dict[Tuple[str, str], int] = defaultdict(int)
        self._type_dist: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._cascade_count: Dict[str, int] = defaultdict(int)
        self._total_bytes: Dict[Tuple[str, str], int] = defaultdict(int)

    def update_from_observation(self, obs: dict):
        messages = obs.get("messages", [])
        for m in messages:
            src = m.get("src", "")
            dst = m.get("dst", "")
            msg_type = m.get("msg_type", "request")
            data_size = int(m.get("data_size", 0))
            ts = int(m.get("timestamp_ns", 0))
            rec = UtteranceRecord(src, dst, msg_type, data_size, ts)
            self._messages.append(rec)
            self._src_dst_count[(src, dst)] += 1
            self._type_dist[(src, dst)][msg_type] += 1
            self._cascade_count[dst] += 1
            self._total_bytes[(src, dst)] += data_size

    def get_frequency(self, src: str, dst: str) -> int:
        return self._src_dst_count.get((src, dst), 0)

    def get_cascade_count(self, agent_id: str) -> int:
        return self._cascade_count.get(agent_id, 0)

    def get_type_distribution(self, src: str, dst: str) -> dict:
        return dict(self._type_dist.get((src, dst), {}))

    def get_total_bytes(self, src: str, dst: str) -> int:
        return self._total_bytes.get((src, dst), 0)

    def to_pyg_data(self, agent_ids: list):
        try:
            import torch
        except ImportError:
            return None
        n = len(agent_ids)
        if n == 0:
            return None
        aid_to_idx = {a: i for i, a in enumerate(agent_ids)}
        x = torch.zeros((n, 4), dtype=torch.float)
        for i, aid in enumerate(agent_ids):
            cascade = self.get_cascade_count(aid) / max(
                (sum(self._cascade_count.values()) or 1), 1
            )
            x[i] = torch.tensor([0.0, 0.0, cascade, 0.0])
        edge_indices = []
        edge_attrs = []
        for (src, dst), count in self._src_dst_count.items():
            i, j = aid_to_idx.get(src), aid_to_idx.get(dst)
            if i is None or j is None:
                continue
            edge_indices.append([i, j])
            total = max(sum(self._src_dst_count.values()), 1)
            edge_attrs.append([
                count / total,
                self._total_bytes.get((src, dst), 0) / max(total, 1),
                0.0, 0.0, 0.0, 0.0,
            ])
        edge_index = torch.tensor(edge_indices, dtype=torch.long).t() if edge_indices else torch.zeros((2, 0), dtype=torch.long)
        edge_attr_t = torch.tensor(edge_attrs, dtype=torch.float) if edge_attrs else torch.zeros((0, 6), dtype=torch.float)
        return (x, edge_index, edge_attr_t)

    @property
    def message_count(self):
        return len(self._messages)

    def clear(self):
        self._messages.clear()
        self._src_dst_count.clear()
        self._type_dist.clear()
        self._cascade_count.clear()
        self._total_bytes.clear()
