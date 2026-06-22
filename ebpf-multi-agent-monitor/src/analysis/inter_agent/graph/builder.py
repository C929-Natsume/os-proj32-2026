import networkx as nx
import numpy as np
from typing import Dict, List, Optional, Tuple


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
                    weight=it.get("weight", 1.0),
                    timestamp_ns=it.get("timestamp_ns", 0),
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

    def to_pyg_data(self):
        try:
            import torch
        except ImportError:
            return None
        n = self.node_count
        if n == 0:
            return None
        x = torch.zeros((n, 14), dtype=torch.float)
        edge_indices = []
        edge_attrs = []
        type_map = {"api_call": 0, "message": 1, "file_share": 2}
        for u, v, d in self._graph.edges(data=True):
            i = self._agent_to_idx.get(u)
            j = self._agent_to_idx.get(v)
            if i is None or j is None:
                continue
            edge_indices.append([i, j])
            t = type_map.get(d.get("type", "message"), 1)
            w = d.get("weight", 1.0)
            edge_attrs.append([t, w, 0.0, 0.0, 0.0, 0.0])
        edge_index = torch.tensor(edge_indices, dtype=torch.long).t() if edge_indices else torch.zeros((2, 0), dtype=torch.long)
        edge_attr_t = torch.tensor(edge_attrs, dtype=torch.float) if edge_attrs else torch.zeros((0, 6), dtype=torch.float)
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
