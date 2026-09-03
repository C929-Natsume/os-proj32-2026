from typing import Dict, List, Optional, Set


class TopologyIntervention:
    """Topology-based intervention through edge pruning and agent isolation.

    When anomaly risk exceeds thresholds, prunes interaction edges to
    contain the spread (similar to network-level containment strategies).
    """

    def __init__(self, auto_isolate_risk=0.8):
        self._auto_isolate = auto_isolate_risk
        self._pruned_edges: List[tuple] = []
        self._isolated_agents: Set[str] = set()
        self._whitelist: Set[str] = set()

    def add_whitelist(self, agent_id: str):
        self._whitelist.add(agent_id)

    def intervene(self, graph, report: dict, propagation: dict) -> dict:
        actions = []
        risk_scores = report.get("risk_scores", {})
        prop_paths = propagation.get("propagation_paths", [])
        sources = propagation.get("source_agents", [])

        for src in sources:
            if src in self._whitelist:
                continue
            risk = risk_scores.get(src, 0)
            if risk >= self._auto_isolate:
                self._isolated_agents.add(src)
                actions.append({
                    "type": "isolate",
                    "agent": src,
                    "risk": risk,
                    "reason": f"risk={risk:.2f} >= auto_isolate={self._auto_isolate}",
                })

                try:
                    edges_to_remove = list(graph.in_edges(src)) + list(graph.out_edges(src))
                except Exception:
                    import logging
                    logging.getLogger(__name__).exception("get edges for %s", src)
                    edges_to_remove = []
                for u, v in edges_to_remove:
                    self._pruned_edges.append((u, v))
                    try:
                        graph.remove_edge(u, v)
                    except Exception:
                        import logging
                        logging.getLogger(__name__).warning("remove_edge(%s, %s) failed", u, v)

        for path_info in prop_paths:
            path = path_info.get("path", [])
            if len(path) < 2:
                continue
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                if u in self._isolated_agents or v in self._isolated_agents:
                    continue
                if (u, v) in self._pruned_edges:
                    continue
                self._pruned_edges.append((u, v))
                actions.append({
                    "type": "prune_edge",
                    "src": u, "dst": v,
                    "reason": f"propagation path hop {i}",
                })

        return {
            "actions": actions,
            "pruned_edges": list(self._pruned_edges),
            "isolated_agents": list(self._isolated_agents),
        }

    @property
    def isolated(self):
        return list(self._isolated_agents)

    def clear(self):
        self._pruned_edges.clear()
        self._isolated_agents.clear()
        self._whitelist.clear()
