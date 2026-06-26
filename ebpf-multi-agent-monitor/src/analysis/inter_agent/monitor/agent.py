import logging
import json
import base64
import os
from datetime import datetime
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
from inter_agent.detection.semantic_rule_checker import SemanticRuleChecker
from inter_agent.intervention.topology import TopologyIntervention


logger = logging.getLogger(__name__)


class ResponseLevel(Enum):
    PASS = "PASS"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"
    LLM_ESCALATE = "LLM_ESCALATE"


_RESPONSE_RANK = {
    ResponseLevel.PASS: 0,
    ResponseLevel.ALERT: 1,
    ResponseLevel.BLOCK: 2,
    ResponseLevel.ISOLATE: 3,
    ResponseLevel.LLM_ESCALATE: 4,
}


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
    semantic_result: dict = field(default_factory=dict)


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
        self._detect_cfg = detect_cfg

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
            latent_dim=model_cfg.get("latent_dim", 64),
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

        self._semantic_threshold = detect_cfg.get("semantic_rule_threshold", 0.5)
        self._semantic_rule_checker = SemanticRuleChecker(
            risk_threshold=self._semantic_threshold)
        self._semantic_rule_weight = detect_cfg.get("semantic_rule_weight", 0.15)

        
        self._gnn_weight = detect_cfg.get("gnn_weight", 0.35)
        self._rule_weight = detect_cfg.get("rule_weight", 0.35)
        self._temporal_weight = detect_cfg.get("temporal_weight", 0.15)

        self._history: List[dict] = []
        self._last_report: Optional[AnomalyReport] = None
        self._consecutive_anomaly_steps: Dict[str, int] = {}
        self._log_dir = cfg.get("log", {}).get("output_dir", None)
        self._session_log_file = None
        self._logged_supplemental_types: set = set()

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
        semantic_rule_result = self._semantic_rule_checker.check(obs)

        combined_scores = self._combine_scores(
            rule_result, gnn_result, temporal_result,
            message_result, agent_ids,
            semantic_rule_result,
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

        semantic_result = semantic_rule_result
        sem_risk = semantic_rule_result.get("overall_risk", 0.0)
        if sem_risk >= self._semantic_threshold:
            current_rank = _RESPONSE_RANK.get(response, 0)
            alert_rank = _RESPONSE_RANK[ResponseLevel.ALERT]
            if current_rank < alert_rank:
                response = ResponseLevel.ALERT
                max_risk = max(max_risk, sem_risk)

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
            semantic_result=semantic_result,
        )

        self._history.append(obs)
        self._last_report = report

        # ── Session-based log output ──
        try:
            _ensure_log_file(self)
            log_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if anomalous_nodes:
                log_text = self._format_anomaly_log(report, obs)
                if log_text:
                    with open(self._session_log_file, "a", encoding="utf-8") as f:
                        f.write(log_text + "\n")
                    logger.info("\n" + log_text)
            else:
                entry = f"[NORMAL] pass  time={log_dt}  agents={len(agent_ids)}  risk={max_risk:.3f}\n"
                with open(self._session_log_file, "a", encoding="utf-8") as f:
                    f.write(entry)
                logger.info("\n" + entry.rstrip("\n"))
        except Exception as e:
            logger.error("Log write failed: %s", e)

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
                        message_result, agent_ids, semantic_rule_result=None):
        scores = {}
        rule_scores = rule_result.get("scores", {})
        temporal_scores = temporal_result.get("temporal_scores", {})
        gnn_scores_list = gnn_result.get("anomaly_scores", [])
        sem_scores = semantic_rule_result.get("agents", {}) if semantic_rule_result else {}

        for i, aid in enumerate(agent_ids):
            r = rule_scores.get(aid, 0.0)
            t = temporal_scores.get(aid, 0.0)
            g = float(gnn_scores_list[i]) if i < len(gnn_scores_list) else 0.0
            s = sem_scores.get(aid, 0.0)
            intra = self._get_intra_anomaly_risk(aid)
            scores[aid] = min(max(r, t, g, s, intra), 1.0)

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
        threshold = self._detect_cfg.get("anomaly_threshold", 0.3)
        anomalous_nodes = [
            aid for aid, s in combined_scores.items()
            if s > threshold
        ]
        gnn_nodes = gnn_result.get("anomaly_nodes", [])
        temporal_nodes = temporal_result.get("anomaly_agents", [])
        gnn_scores_list = gnn_result.get("anomaly_scores", [])
        if gnn_nodes:
            for idx in gnn_nodes:
                if idx < len(agent_ids):
                    aid = agent_ids[idx]
                    g = float(gnn_scores_list[idx]) if idx < len(gnn_scores_list) else 0.0
                    # Only add GNN-flagged node if combined score also exceeds threshold
                    if combined_scores.get(aid, 0) > threshold and aid not in anomalous_nodes:
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
        r_isolate = self._detect_cfg.get("response_isolate", 0.9)
        r_block = self._detect_cfg.get("response_block", 0.7)
        r_alert = self._detect_cfg.get("response_alert", 0.3)
        if max_risk >= r_isolate:
            return ResponseLevel.ISOLATE
        if max_risk >= r_block:
            return ResponseLevel.BLOCK
        if max_risk >= r_alert:
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

    def reset_state(self):
        self._interaction_graph.clear()
        self._utterance_graph.clear()
        self._temporal_detector.clear()
        self._message_detector._baseline.clear()
        self._message_detector._baseline_size.clear()
        self._message_detector._baseline_samples = 0
        self._consecutive_anomaly_steps.clear()

    # ── Log formatting (human-readable) ─────────────────────────────────

    _NODE_TYPES = {"resource", "security", "worker_isolated",
        "reasoning_action_mismatch", "wrong_assumption", "task_derailment",
        "concealment", "premature_convergence", "stale_state", "partial_visibility",
        "timeout_retry"}
    _EDGE_TYPES = {"state_conflict", "message_disorder", "ignore_input",
        "group_split", "supervisor_bypass", "flood_from_single",
        "message_storm", "propagation"}
    _VIEW_TYPES = {"propagation", "group_split", "message_storm",
        "flood_from_single", "premature_convergence"}
    _SEMANTIC_TYPES = {"stale_state", "state_conflict", "partial_visibility",
        "message_disorder", "timeout_retry", "ignore_input",
        "reasoning_action_mismatch", "wrong_assumption", "task_derailment",
        "concealment", "premature_convergence"}

    def _classify_module(self, anom_type: str) -> str:
        if anom_type in self._NODE_TYPES:
            return "node"
        if anom_type in self._EDGE_TYPES:
            return "edge"
        if anom_type in self._VIEW_TYPES:
            return "view"
        return "unknown"

    def _collect_events(self, obs: dict, agent_ids: list,
                         num: int = 8) -> list:
        events = []
        msgs = obs.get("messages", [])
        for m in msgs:
            src = m.get("src", "?")
            if src in agent_ids:
                try:
                    raw = m.get("data", "")
                    try:
                        text = base64.b64decode(raw).decode("utf-8")[:80]
                    except UnicodeDecodeError:
                        text = f"[bin:{raw[:24]}...]"
                    if not text or not any(c.isalpha() for c in text[:20]):
                        text = (raw[:40] + "...") if raw else "..."
                except Exception:
                    text = (raw[:40] + "...") if raw else "..."
                events.append({
                    "ts": m.get("timestamp_ns", 0),
                    "agent": src,
                    "pid": "",
                    "op": m.get("msg_type", "unknown"),
                    "target": m.get("dst", "?"),
                    "detail": text,
                })
        for it in obs.get("interactions", []):
            src = it.get("src", "")
            if src in agent_ids:
                events.append({
                    "ts": it.get("timestamp_ns", 0),
                    "agent": src,
                    "pid": "",
                    "op": it.get("type", "unknown"),
                    "target": it.get("dst", "?"),
                    "detail": "",
                })
        return events[:num]

    def _build_semantic_context(self, obs: dict, atype: str,
                                 agent_id: str) -> dict:
        if atype not in self._SEMANTIC_TYPES:
            return {}
        msgs = obs.get("messages", [])
        for m in msgs:
            if m.get("src") == agent_id:
                try:
                    raw = m.get("data", "")
                    text = base64.b64decode(raw).decode("utf-8",
                                                         errors="replace")
                except Exception:
                    text = ""
                if len(text) > 10:
                    return {
                        "sender": agent_id,
                        "receiver": m.get("dst", "?"),
                        "content": text[:200],
                    }
        return {}

    def _analyze_view(self, obs: dict, atype: str) -> dict:
        agents = obs.get("agents", {})
        n = len(agents)
        interactions = obs.get("interactions", [])
        m = len(interactions)
        topo = obs.get("_topology", "unknown")
        agent_list = sorted(agents.keys())
        agents_str = ", ".join(agent_list[:8])
        if n > 8:
            agents_str += f" ...(+{n-8})"
        return {
            "topology": topo,
            "agents": n,
            "edges": m,
            "agent_list": agents_str,
        }

    def _format_anomaly_log(self, report, obs: dict,
                             output_dir: str = None) -> str:
        if not report.anomalous_nodes:
            return ""

        lines = []
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        agent_ids = list(obs.get("agents", {}).keys())
        evidence = {}
        try:
            evidence = self._semantic_rule_checker.get_evidence(obs)
        except Exception:
            pass

        import re
        seen = set()
        dup_count = 0
        sem_types = report.semantic_result.get("anomaly_types", []) if report.semantic_result else []
        obs_type = obs.get("_anomaly_type", "") if isinstance(obs, dict) else ""
        first_type = sem_types[0] if sem_types else (obs_type if obs_type and obs_type != "normal" else "unknown")
        other_types = [t for t in sem_types[1:] if t != first_type]

        seen = set()
        dup_count = 0
        for aid in report.anomalous_nodes:
            gnn_scores = report.gnn_risks
            risk = max(report.max_risk,
                       gnn_scores.get(aid, 0),
                       report.semantic_result.get("overall_risk", 0)
                       if report.semantic_result else 0)

            atype = first_type
            module = self._classify_module(atype)
            is_sem = atype in self._SEMANTIC_TYPES
            severity = "HIGH" if risk >= 0.8 else ("MEDIUM" if risk >= 0.5
                                                     else "LOW")

            ev = evidence.get(aid, {}).get(atype, {})
            try:
                if ev:
                    cause = self._semantic_rule_checker.get_root_cause(atype, ev)
                else:
                    cause = f"Anomaly type '{atype}' detected on {aid}"
            except Exception:
                cause = f"Anomaly type '{atype}' detected on {aid}"

            cause_norm = re.sub(r"detected on \S+", "detected on <agent>", cause)
            sig = (atype, severity, cause_norm)
            if sig in seen:
                dup_count += 1
                continue
            seen.add(sig)

            self._write_entry(lines, module, atype, severity, risk, aid,
                              cause, obs, agent_ids, ts, is_sem)
        if dup_count:
            lines.append(f"  ... and {dup_count} duplicate alerts suppressed")

        # Supplementary entries for non-dominant detected types
        for atype in other_types:
            if atype in self._logged_supplemental_types:
                continue
            self._logged_supplemental_types.add(atype)
            module = self._classify_module(atype)
            is_sem = atype in self._SEMANTIC_TYPES
            severity = "HIGH"
            cause = f"Anomaly type '{atype}' detected in observation"
            self._write_entry(lines, module, atype, severity, 1.0,
                              "unknown", cause, obs, agent_ids, ts, is_sem)

        log_text = "\n".join(lines)
        return log_text

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

    def _write_entry(self, lines, module, atype, severity, risk, aid,
                     cause, obs, agent_ids, ts, is_sem):
        lines.append("=" * 54)
        lines.append(f"[{module}] {atype} ({severity})")
        lines.append(f"risk={risk:.3f}  time={ts}")
        ebpf_pid = obs.get("agents", {}).get(aid, {}).get("_ebpf_pid", "")
        if ebpf_pid:
            lines.append(f"agent={aid}  ebpf={ebpf_pid}")
        lines.append("-" * 54)
        events = self._collect_events(obs, agent_ids)
        lines.append("[event sequence]")
        for e in events[:6]:
            detail = (e["detail"][:40] + "...") if len(
                e["detail"]) > 40 else e["detail"]
            if detail:
                lines.append(f'  - {e["agent"]}  {e["op"]} -> {e["target"]}  "{detail}"')
            else:
                lines.append(f"  - {e['agent']}  {e['op']} -> {e['target']}")
        if is_sem:
            ctx = self._build_semantic_context(obs, atype, aid)
            if ctx:
                lines.append("[semantic association]")
                lines.append(f"  sender: {ctx['sender']}"
                             f" -> receiver: {ctx['receiver']}")
                lines.append(f'  content: "{ctx["content"][:160]}"')
        lines.append("[root cause]")
        lines.append(f"  {cause}")
        view = self._analyze_view(obs, atype)
        lines.append("[view]")
        lines.append(f"  topology={view['topology']}"
                     f"  agents={view['agents']}"
                     f"  edges={view['edges']}")
        if view['agent_list']:
            lines.append(f"  agents: {view['agent_list']}")
        lines.append("=" * 54)
        lines.append("")


def _ensure_log_file(agent):
    if agent._session_log_file is None:
        od = agent._log_dir
        if od is None:
            od = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                '..', '..', '..', '..', 'logs', 'inter_log')
        os.makedirs(od, exist_ok=True)
        dt = datetime.now().strftime('%Y%m%d_%H%M%S')
        agent._session_log_file = os.path.join(od, f'anomaly_{dt}.log')
