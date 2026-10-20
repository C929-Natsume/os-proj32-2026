from collections import deque
from typing import Dict, List, Optional, Tuple


class PropagationPathAnalyzer:
    """BFS-based propagation path tracking across agent interaction graph.

    Identifies how anomalies spread from source agents through the
    interaction topology (analogous to process tree propagation in
    intra_agent's proc_tree.c).
    """

    def __init__(self, max_hops=4, risk_threshold=0.5):
        self._max_hops = max_hops
        self._risk_threshold = risk_threshold
        self._graph = None

    def update_graph(self, agent_graph):
        self._graph = agent_graph

    def analyze(self, anomalous_nodes: list, anomalous_edges: list,
                agent_mapping: dict = None) -> dict:
        if not self._graph or not anomalous_nodes:
            return {
                "propagation_paths": [],
                "source_agents": [],
                "total_risk": 0.0,
                "edge_anomalies": [],
            }

        nx_graph = self._graph
        sources = self._identify_sources(anomalous_nodes, agent_mapping)

        all_paths = []
        total_risk = 0.0

        for src in sources:
            paths = self._bfs_propagate(src, anomalous_nodes)
            for p in paths:
                hop_risk = 1.0 / (1.0 + len(p["path"]))
                p["risk"] = hop_risk if len(p["path"]) > 1 else 0.3
                total_risk += p["risk"]
                all_paths.append(p)

        edge_anomalies = self._analyze_edge_anomalies(
            anomalous_edges, agent_mapping
        )
        total_risk += sum(e.get("risk", 0) for e in edge_anomalies)

        return {
            "propagation_paths": all_paths,
            "source_agents": sources,
            "total_risk": min(total_risk, 1.0),
            "edge_anomalies": edge_anomalies,
        }

    def _identify_sources(self, anomalous_nodes: list,
                          agent_mapping: dict = None) -> list:
        if agent_mapping and len(anomalous_nodes) > 0:
            idx_to_agent = {v: k for k, v in agent_mapping.items()}
            return [
                idx_to_agent.get(n, str(n))
                for n in anomalous_nodes
                if n in idx_to_agent
            ]
        return anomalous_nodes if anomalous_nodes else []

    def _bfs_propagate(self, source: str, anomalous_nodes: list) -> list:
        paths = []
        visited = {source}
        queue = deque([(source, [source], 0)])

        anom_set = set(anomalous_nodes)
        if source not in anom_set:
            anom_set.add(source)

        while queue:
            current, path, depth = queue.popleft()
            if depth >= self._max_hops:
                continue

            try:
                neighbors = list(self._graph.successors(current))
            except Exception:
                import logging
                logging.getLogger(__name__).exception("get successors for %s", current)
                neighbors = []

            for nbr in neighbors:
                if nbr in visited:
                    continue
                visited.add(nbr)
                new_path = path + [nbr]
                paths.append({
                    "path": list(new_path),
                    "hop": depth + 1,
                    "source": source,
                    "target": nbr,
                    "is_anomalous": nbr in anom_set,
                })
                if nbr in anom_set and depth + 1 < self._max_hops:
                    queue.append((nbr, new_path, depth + 1))

        return paths

    def _analyze_edge_anomalies(self, anomalous_edges: list,
                                agent_mapping: dict = None) -> list:
        results = []
        for edge in (anomalous_edges or []):
            if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                u, v = edge[0], edge[1]
                results.append({
                    "src": u, "dst": v,
                    "risk": min(0.5 + len(edge) * 0.1 if len(edge) > 2 else 0.5, 1.0),
                    "type": "edge_anomaly",
                })
        return results
