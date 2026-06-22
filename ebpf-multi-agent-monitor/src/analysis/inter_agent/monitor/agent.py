import logging
import json
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from inter_agent.graph.builder import AgentInteractionGraph
from inter_agent.graph.feature_extractor import FeatureExtractor
from inter_agent.graph.utterance_graph import UtteranceGraph
from inter_agent.detection.gnn_detector import AnomalyDetector, RuleBasedDetector, extract_features
from inter_agent.detection.temporal_detector import TemporalAnomalyDetector
from inter_agent.detection.message_detector import MessageAnomalyDetector
from inter_agent.detection.propagation_analyzer import PropagationPathAnalyzer
from inter_agent.intervention.topology import TopologyIntervention
from inter_agent.llm.client import LLMEscalator

logger = logging.getLogger(__name__)


class ResponseLevel(Enum):
    PASS = "PASS"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"
    LLM_ESCALATE = "LLM_ESCALATE"


@dataclass
class AnomalyReport:
    timestamp_ns: int = 0
    response_level: ResponseLevel = ResponseLevel.PASS
    max_risk: float = 0.0
    rule_risks: Dict[str, float] = field(default_factory=dict)
    gnn_risks: Dict[str, float] = field(default_factory=dict)
    temporal_risks: Dict[str, float] = field(default_factory=dict)
    message_anomalies: list = field(default_factory=list)
    propagation_results: dict = field(default_factory=dict)
    intervention_actions: list = field(default_factory=list)
    anomalous_nodes: List[str] = field(default_factory=list)
    anomalous_edges: List[tuple] = field(default_factory=list)
    source_agent: Optional[str] = None
    state_view: dict = field(default_factory=dict)
    llm_escalated: bool = False
    llm_verdict: Optional[dict] = None
    escalation_context: dict = field(default_factory=dict)


class MonitorAgent:
    """Main coordinator for inter-agent anomaly detection.

    Processes observations from RedisCollector through a 6-step pipeline:
      1. Graph construction (AgentInteractionGraph + UtteranceGraph)
      2. Feature extraction
      3. Rule-based + GNN anomaly detection
      4. Temporal anomaly detection
      5. Message anomaly detection
      6. Propagation analysis + Topology intervention
    """

    def __init__(self, config: Optional[dict] = None, model_path: Optional[str] = None):
        cfg = config or {}
        detect_cfg = cfg.get("detection", {})

        self._interaction_graph = AgentInteractionGraph(
            max_agents=cfg.get("agents", {}).get("max_agents", 16)
        )
        self._utterance_graph = UtteranceGraph()
        self._feature_extractor = FeatureExtractor()
        self._rule_detector = RuleBasedDetector(detect_cfg)
        model_cfg = cfg.get("model", {})
        self._gnn_detector = AnomalyDetector(
            node_dim=model_cfg.get("node_dim", 14),
            hidden_dim=model_cfg.get("hidden_dim", 64),
            latent_dim=model_cfg.get("latent_dim", 16),
            feature_weight=model_cfg.get("feature_weight", 0.3),
            model_path=model_path or model_cfg.get("model_path"),
        )
        self._temporal_detector = TemporalAnomalyDetector(
            window_size=detect_cfg.get("temporal_window", 10),
            risk_threshold=detect_cfg.get("temporal_risk_threshold", 0.6),
        )
        self._message_detector = MessageAnomalyDetector(
            freq_std_threshold=detect_cfg.get("message_freq_std_threshold", 2.5),
            cascade_threshold=detect_cfg.get("cascade_agent_threshold", 5),
            data_size_mb=detect_cfg.get("data_size_mb_threshold", 100.0),
        )
        self._propagation_analyzer = PropagationPathAnalyzer(
            max_hops=detect_cfg.get("propagation_max_hops", 4),
            risk_threshold=detect_cfg.get("propagation_risk_threshold", 0.5),
        )
        self._intervention = TopologyIntervention(
            auto_isolate_risk=cfg.get("intervention", {}).get("auto_isolate_risk", 0.8),
        )

        llm_cfg = cfg.get("llm", {})
        self._llm_escalator = LLMEscalator(
            api_key=llm_cfg.get("api_key"),
            model_name=llm_cfg.get("model_name", "deepseek-chat"),
            base_url=llm_cfg.get("base_url", "https://api.deepseek.com/v1"),
            enabled=llm_cfg.get("enabled", False),
        )
        self._llm_threshold = detect_cfg.get("llm_escalation_threshold", 0.7)
        self._gnn_weight = detect_cfg.get("gnn_weight", 0.4)
        self._rule_weight = detect_cfg.get("rule_weight", 0.4)
        self._temporal_weight = detect_cfg.get("temporal_weight", 0.2)

        self._history: List[dict] = []
        self._last_report: Optional[AnomalyReport] = None
        self._consecutive_anomaly_steps: Dict[str, int] = {}

    def process_observation(self, obs: dict) -> AnomalyReport:
        ts = obs.get("timestamp", 0)

        self._interaction_graph.update_from_observation(obs)
        self._utterance_graph.update_from_observation(obs)

        self._temporal_detector.update(obs)
        self._message_detector.update_baseline(obs)

        agents_data = obs.get("agents", {})
        agent_ids = list(agents_data.keys())

        rule_result = self._rule_detector.detect(agents_data)
        gnn_result = self._detect_gnn(obs, agents_data, agent_ids)
        temporal_result = self._temporal_detector.detect()
        message_result = self._message_detector.detect(obs)

        combined_scores = self._combine_scores(
            rule_result, gnn_result, temporal_result,
            message_result, agent_ids
        )

        anomalous_nodes, anomalous_edges = self._identify_anomalies(
            combined_scores, gnn_result, temporal_result, agent_ids
        )
        source = self._identify_source(
            combined_scores, gnn_result, message_result, anomalous_nodes
        )

        self._propagation_analyzer.update_graph(
            self._interaction_graph.graph
        )
        propagation_result = self._propagation_analyzer.analyze(
            anomalous_nodes, anomalous_edges,
            self._interaction_graph.agent_mapping
        )

        max_risk = max(combined_scores.values()) if combined_scores else 0.0
        response = self._decide_response(
            max_risk, combined_scores, anomalous_nodes,
            propagation_result, agent_ids
        )
        if response == ResponseLevel.ISOLATE and source:
            self._intervention.add_whitelist(source)

        intervention_result = self._intervention.intervene(
            self._interaction_graph.graph,
            {"risk_scores": combined_scores},
            propagation_result,
        )

        state = self._build_state_view(
            obs, combined_scores, anomalous_nodes, response,
            propagation_result, intervention_result
        )

        gnn_scores = gnn_result.get("anomaly_scores", [])
        escalation_context = self._build_escalation_context(
            obs, combined_scores, gnn_result, agent_ids,
            anomalous_nodes, source, propagation_result,
        )
        llm_escalated = False
        llm_verdict = None
        if (max_risk >= self._llm_threshold and anomalous_nodes
                and self._llm_escalator.is_enabled):
            llm_verdict = self._llm_escalator.evaluate(escalation_context)
            llm_escalated = True
            response = ResponseLevel.LLM_ESCALATE

        report = AnomalyReport(
            timestamp_ns=ts,
            response_level=response,
            max_risk=max_risk,
            rule_risks=rule_result.get("scores", {}),
            gnn_risks={
                aid: float(gnn_scores[i])
                for i, aid in enumerate(agent_ids)
                if i < len(gnn_scores)
            },
            temporal_risks=temporal_result.get("temporal_scores", {}),
            message_anomalies=message_result.get("anomalies", []),
            propagation_results=propagation_result,
            intervention_actions=intervention_result.get("actions", []),
            anomalous_nodes=anomalous_nodes,
            anomalous_edges=anomalous_edges,
            source_agent=source,
            state_view=state,
            llm_escalated=llm_escalated,
            llm_verdict=llm_verdict,
            escalation_context=escalation_context,
        )

        self._history.append(obs)
        self._last_report = report
        return report

    def _detect_gnn(self, obs: dict, agents_data: dict, agent_ids: list) -> dict:
        pyg_data = self._interaction_graph.to_pyg_data()
        if pyg_data is None or not agent_ids:
            return {"anomaly_scores": [], "anomaly_nodes": [], "recon_error": 0.0,
                    "cls_probability": [], "graph_score": 0.0}
        _, edge_index, _ = pyg_data
        x_np = extract_features(agents_data, agent_ids, obs.get("interactions", []))
        return self._gnn_detector.detect(x_np, edge_index)

    def _combine_scores(self, rule_result, gnn_result, temporal_result,
                        message_result, agent_ids):
        scores = {}
        rule_scores = rule_result.get("scores", {})
        temporal_scores = temporal_result.get("temporal_scores", {})
        gnn_scores_list = gnn_result.get("anomaly_scores", [])

        use_gnn = (self._gnn_detector.is_loaded and len(gnn_scores_list) > 0)

        for i, aid in enumerate(agent_ids):
            r = rule_scores.get(aid, 0.0)
            t = temporal_scores.get(aid, 0.0)
            g = float(gnn_scores_list[i]) if i < len(gnn_scores_list) else 0.0
            intra = self._get_intra_anomaly_risk(aid)
            if use_gnn:
                scores[aid] = min(
                    self._rule_weight * r + self._gnn_weight * g
                    + self._temporal_weight * t + intra,
                    1.0
                )
            else:
                scores[aid] = min(max(r, t, g, intra), 1.0)

        for anom in message_result.get("anomalies", []):
            a_type = anom.get("type", "")
            src = anom.get("src", "")
            dst = anom.get("dst", "")
            risk = float(anom.get("risk", 0.3))
            if src in scores:
                scores[src] = min(max(scores[src], risk), 1.0)
            if dst in scores:
                scores[dst] = min(max(scores[dst], risk * 0.8), 1.0)
            if a_type == "cascade_storm" and dst in scores:
                scores[dst] = min(max(scores[dst], risk), 1.0)
            if a_type == "intra_agent_alert" and src in scores:
                scores[src] = min(max(scores[src], risk), 1.0)

        return scores

    def _get_intra_anomaly_risk(self, agent_id: str) -> float:
        if agent_id in self._consecutive_anomaly_steps:
            steps = self._consecutive_anomaly_steps[agent_id]
            if steps > 2:
                return min(0.1 * (steps - 2), 0.5)
        return 0.0

    def _identify_anomalies(self, combined_scores, gnn_result,
                            temporal_result, agent_ids):
        threshold = 0.5
        anomalous_nodes = [
            aid for aid, s in combined_scores.items()
            if s > threshold
        ]
        gnn_nodes = gnn_result.get("anomaly_nodes", [])
        temporal_nodes = temporal_result.get("anomaly_agents", [])
        if gnn_nodes:
            for idx in gnn_nodes:
                if idx < len(agent_ids):
                    aid = agent_ids[idx]
                    if aid not in anomalous_nodes:
                        anomalous_nodes.append(aid)
        for aid in temporal_nodes:
            if aid not in anomalous_nodes:
                anomalous_nodes.append(aid)
        anomalous_edges = []
        return anomalous_nodes, anomalous_edges

    def _identify_source(self, combined_scores, gnn_result,
                         message_result, anomalous_nodes):
        candidates = sorted(anomalous_nodes, key=lambda a: combined_scores.get(a, 0), reverse=True)
        if candidates:
            return candidates[0]
        if message_result.get("anomalies"):
            for a in message_result["anomalies"]:
                if a.get("type") == "frequency_surge":
                    return a.get("src")
                if a.get("type") == "cascade_storm":
                    return a.get("dst")
        return None

    def _decide_response(self, max_risk, scores, anomalous_nodes,
                         propagation_result, agent_ids):
        if max_risk >= 0.9:
            return ResponseLevel.ISOLATE
        if max_risk >= 0.7:
            return ResponseLevel.BLOCK
        if max_risk >= 0.4:
            return ResponseLevel.ALERT
        return ResponseLevel.PASS

    def _build_state_view(self, obs, scores, anomalous_nodes, response,
                          propagation_result, intervention_result):
        return {
            "timestamp": obs.get("timestamp", 0),
            "agent_count": len(obs.get("agents", {})),
            "message_count": len(obs.get("messages", [])),
            "anomaly_count": len(anomalous_nodes),
            "response": response.value,
            "max_risk": max(scores.values()) if scores else 0.0,
            "risk_scores": dict(scores),
            "anomalous_agents": anomalous_nodes,
            "propagation_paths": propagation_result.get("propagation_paths", []),
            "source_agents": propagation_result.get("source_agents", []),
            "intervention_actions": intervention_result.get("actions", []),
            "pruned_edges": intervention_result.get("pruned_edges", []),
            "isolated_agents": intervention_result.get("isolated_agents", []),
        }

    def _build_escalation_context(self, obs, combined_scores, gnn_result,
                                   agent_ids, anomalous_nodes, source,
                                   propagation_result):
        gnn_scores = gnn_result.get("anomaly_scores", [])
        cls_probs = gnn_result.get("cls_probability", [])
        return {
            "timestamp_ns": obs.get("timestamp", 0),
            "agents": {
                aid: {
                    "risk_score": round(combined_scores.get(aid, 0), 4),
                    "gnn_score": round(float(gnn_scores[i]), 4) if i < len(gnn_scores) else 0,
                    "cls_probability": round(float(cls_probs[i]), 4) if i < len(cls_probs) else 0,
                }
                for i, aid in enumerate(agent_ids)
            },
            "anomalous_agents": anomalous_nodes,
            "source_agent": source,
            "graph_score": round(float(gnn_result.get("graph_score", 0)), 4),
            "recon_error": round(float(gnn_result.get("recon_error", 0)), 4),
            "propagation_paths": propagation_result.get("propagation_paths", []),
            "data_summary": {
                "num_agents": len(agent_ids),
                "num_messages": len(obs.get("messages", [])),
                "num_anomalies": len(obs.get("anomalies", [])),
            },
        }

    def generate_report(self) -> AnomalyReport:
        return self._last_report

    @property
    def interaction_graph(self):
        return self._interaction_graph

    @property
    def utterance_graph(self):
        return self._utterance_graph

    def clear(self):
        self._interaction_graph.clear()
        self._utterance_graph.clear()
        self._temporal_detector.clear()
        self._intervention.clear()
        self._history.clear()
        self._last_report = None
        self._consecutive_anomaly_steps.clear()
