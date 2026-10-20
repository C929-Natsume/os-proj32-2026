import logging
import networkx as nx
import numpy as np
from typing import Dict, List, Optional, Tuple

from inter_agent.data.features import (
    NODE_FEATURE_DIM,
    EDGE_FEATURE_DIM,
    _DATA_SIZE_DIVISOR,
    _MSG_COUNT_DIVISOR,
    extract_node_features,
)

logger = logging.getLogger(__name__)


class AgentInteractionGraph:
    """Agent-level interaction graph built from Redis observation data.

    Maps agent interactions (API calls, messages, file shares) as a
    directed weighted graph, analogous to how intra_agent tracks
    per-PID relationships through process tree (proc_tree.c).
    """

    def __init__(self, max_agents=16):
        self._graph = nx.DiGraph()
        self._max_agents = max_agents
        self._agent_to_idx = {}
        self._idx_to_agent = {}

    def update_from_observation(self, obs: dict):
        agents_data = obs.get("agents", {})
        interactions = obs.get("interactions", [])

        active_agents = set(agents_data.keys())
        if len(active_agents) > self._max_agents:
            logger.warning("Observation has %d agents (max_agents=%d); graph "
                           "will hold all of them.",
                           len(active_agents), self._max_agents)
        for aid in active_agents:
            self._add_agent(aid)

        stale = [a for a in list(self._graph.nodes) if a not in active_agents]
        for a in stale:
            self._graph.remove_node(a)
            if a in self._agent_to_idx:
                idx = self._agent_to_idx.pop(a)
                self._idx_to_agent.pop(idx, None)

        for it in interactions:
            src, dst = it["src"], it["dst"]
            if src in active_agents and dst in active_agents:
                self._add_agent(src)
                self._add_agent(dst)
                self._graph.add_edge(
                    src, dst,
                    type=it.get("type", "message"),
                    weight=it.get("weight", 0.5),
                    timestamp_ns=it.get("timestamp_ns", 0),
                    data_size=float(it.get("data_size", 0)),
                    msg_count=float(it.get("msg_count", 0)),
                )

        self._rebuild_index()

    def _add_agent(self, agent_id: str):
        if agent_id not in self._graph:
            self._graph.add_node(agent_id)

    def _rebuild_index(self):
        self._agent_to_idx.clear()
        self._idx_to_agent.clear()
        for i, node in enumerate(sorted(self._graph.nodes)):
            self._agent_to_idx[node] = i
            self._idx_to_agent[i] = node

    def to_pyg_data(self, agents_data: Optional[dict] = None,
                    interactions: Optional[list] = None):
        try:
            import torch
        except ImportError:
            return None
        n = self.node_count
        if n == 0:
            return None
        node_ids = [self._idx_to_agent[i] for i in range(n)]
        if agents_data is not None:
            x_np = extract_node_features(agents_data, node_ids, interactions)
            x = torch.from_numpy(x_np).float()
        else:
            x = torch.zeros((n, NODE_FEATURE_DIM), dtype=torch.float)
        edge_indices = []
        edge_attrs = []
        # one-hot edge type in TRAINING format: message=0, api_call=1, file_share=2
        type_map = {"message": 0, "api_call": 1, "file_share": 2, "bypass": 1}
        for u, v, d in self._graph.edges(data=True):
            i = self._agent_to_idx.get(u)
            j = self._agent_to_idx.get(v)
            if i is None or j is None:
                continue
            edge_indices.append([i, j])
            t = type_map.get(d.get("type", "message"), 0)
            onehot = [0.0, 0.0, 0.0]
            onehot[t] = 1.0
            w = float(d.get("weight", 0.5))
            ds = min(float(d.get("data_size", 0)) / _DATA_SIZE_DIVISOR, 1.0)
            mc = min(float(d.get("msg_count", 0)) / _MSG_COUNT_DIVISOR, 1.0)
            edge_attrs.append(onehot + [w, ds, mc])
        edge_index = torch.tensor(edge_indices, dtype=torch.long).t() if edge_indices else torch.zeros((2, 0), dtype=torch.long)
        edge_attr_t = torch.tensor(edge_attrs, dtype=torch.float) if edge_attrs else torch.zeros((0, EDGE_FEATURE_DIM), dtype=torch.float)
        return (x, edge_index, edge_attr_t)

    @property
    def graph(self):
        return self._graph

    @property
    def node_count(self):
        return self._graph.number_of_nodes()

    @property
    def edge_count(self):
        return self._graph.number_of_edges()

    def clear(self):
        self._graph.clear()
        self._agent_to_idx.clear()
        self._idx_to_agent.clear()

    def get_num_nodes(self):
        return self.node_count

    @property
    def agent_mapping(self):
        return dict(self._agent_to_idx)
