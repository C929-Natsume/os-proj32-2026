import base64
import logging
import os
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple

from inter_agent.config import load_config
from inter_agent.graph.builder import AgentInteractionGraph
from inter_agent.detection.gnn_detector import AnomalyDetector, RuleBasedDetector
from inter_agent.detection.temporal_detector import TemporalAnomalyDetector
from inter_agent.detection.message_detector import MessageAnomalyDetector
from inter_agent.detection.propagation_analyzer import PropagationPathAnalyzer
from inter_agent.detection.semantic_rule_checker import SemanticRuleChecker
from inter_agent.data.features import NODE_FEATURE_DIM
from inter_agent.data.fingerprint_bank import CommunicationFingerprintBank
from inter_agent.intervention.topology import TopologyIntervention


logger = logging.getLogger(__name__)

# ── Named constants ──────────────────────────────────────────────
HISTORY_MAXLEN = 100
MAX_EVENT_TEXT_LEN = 80
BIN_PREVIEW_LEN = 24
MIN_ALPHA_CHECK = 20
RAW_PREVIEW_LEN = 40
MIN_SEMANTIC_TEXT_LEN = 10
MAX_SEMANTIC_CONTENT_LEN = 200
MAX_AGENTS_TO_LIST = 8
SEVERITY_HIGH_THRESHOLD = 0.8
SEVERITY_MEDIUM_THRESHOLD = 0.5
LINE_SEPARATOR_LEN = 54
MAX_EVENTS_DISPLAY = 6
DETAIL_TRUNCATE_LEN = 40
MAX_CONTENT_TRUNCATE_LEN = 160
SUPPLEMENTAL_SEVERITY_RISK = 1.0
SCORE_BOOST_FACTOR = 0.8
DEFAULT_ANOMALY_RISK = 0.3
MAX_SAME_TYPE_ENTRIES = 3
VIEW_SMALL_MAX_AGENTS = 6
VIEW_SMALL_MAX_EDGES = 16
VIEW_EDGE_LIST_LIMIT = 12
VIEW_LINE_MAX = 90
ROLE_UNKNOWN = "unknown"
# ─────────────────────────────────────────────────────────────────


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
    fingerprint_result: dict = field(default_factory=dict)


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
        self._BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self._interaction_graph = AgentInteractionGraph(
            max_agents=cfg.get("agents", {}).get("max_agents", 16)
        )
        self._rule_detector = RuleBasedDetector(detect_cfg)
        model_cfg = cfg.get("model", {})
        self._gnn_detector = AnomalyDetector(
            node_dim=model_cfg.get("node_dim", NODE_FEATURE_DIM),
            hidden_dim=model_cfg.get("hidden_dim", 64),
            latent_dim=model_cfg.get("latent_dim", 64),
            feature_weight=model_cfg.get("feature_weight", 0.3),
            model_path=self._resolve_path(model_path or model_cfg.get("model_path")),
            sparse_struct=model_cfg.get("sparse_struct", False),
        )
        self._temporal_detector = TemporalAnomalyDetector(
            window_size=detect_cfg.get("temporal_window", 10),
            risk_threshold=detect_cfg.get("temporal_risk_threshold", 0.6),
        )
        self._message_detector = MessageAnomalyDetector(
            freq_std_threshold=detect_cfg.get("message_freq_std_threshold", 2.5),
            cascade_threshold=detect_cfg.get("cascade_agent_threshold", 8),
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
        self._anomaly_threshold = detect_cfg.get("anomaly_threshold", 0.3)
        semantic_cfg = detect_cfg.get("semantic", {})
        posterior_path = semantic_cfg.get("posterior_path")
        posterior_path = self._resolve_path(posterior_path)
        self._semantic_rule_checker = SemanticRuleChecker(
            risk_threshold=self._semantic_threshold,
            adaptive=bool(semantic_cfg.get("adaptive", False)),
            adaptive_cfg=semantic_cfg,
            posterior_path=posterior_path)
        self._semantic_rule_weight = detect_cfg.get("semantic_rule_weight", 0.15)

        fp_cfg = detect_cfg.get("fingerprint", {})
        bank_path = fp_cfg.get("bank_path")
        bank_path = self._resolve_path(bank_path)
        self._fingerprint_bank = CommunicationFingerprintBank(
            enabled=bool(fp_cfg.get("enabled", False)),
            forget_alpha=fp_cfg.get("forget_alpha", 0.1),
            z_threshold=fp_cfg.get("z_threshold", 3.0),
            min_samples=fp_cfg.get("min_samples", 5),
            unknown_penalty=fp_cfg.get("unknown_penalty", 1.0),
            magnitude_scale=fp_cfg.get("magnitude_scale", 2.0),
            save_path=bank_path,
        )
        self._fingerprint_weight = fp_cfg.get("weight", 0.1)
        self._fingerprint_learn_online = bool(fp_cfg.get("learn_online", True))
        if self._fingerprint_bank.enabled:
            self._fingerprint_bank.load()

        self._history: deque = deque(maxlen=HISTORY_MAXLEN)
        self._last_report: Optional[AnomalyReport] = None
        self._log_dir = self._resolve_path(
            cfg.get("log", {}).get("output_dir", None))
        self._session_log_file = None
        self._logged_supplemental_types: set = set()

    @staticmethod
    def _resolve_path(path: Optional[str]) -> Optional[str]:
        if path and not os.path.isabs(path):
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            return os.path.join(base, path)
        return path

    def process_observation(self, obs: dict) -> AnomalyReport:
        ts = obs.get("timestamp", 0)

        self._interaction_graph.update_from_observation(obs)

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

        p_anomaly = max(combined_scores.values()) if combined_scores else 0.0
        self._semantic_rule_checker.update(obs, p_anomaly=p_anomaly)

        fingerprint_result = {}
        if self._fingerprint_bank.enabled:
            interactions = obs.get("interactions", [])
            fingerprint_result = self._fingerprint_bank.score(interactions)
            if (self._fingerprint_learn_online
                    and max(combined_scores.values(), default=0.0)
                    < self._anomaly_threshold):
                self._fingerprint_bank.learn(interactions)
                self._fingerprint_bank.save()

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
        if fingerprint_result and fingerprint_result.get("risk", 0.0) > 0.0:
            max_risk = max(max_risk, self._fingerprint_weight * fingerprint_result["risk"])
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
            sem_agents = semantic_rule_result.get("agents", {})
            for aid, risk in sem_agents.items():
                if risk > 0 and aid not in anomalous_nodes:
                    anomalous_nodes.append(aid)

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
            fingerprint_result=fingerprint_result,
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
        interactions = obs.get("interactions", [])
        pyg_data = self._interaction_graph.to_pyg_data(agents_data, interactions)
        if pyg_data is None or not agent_ids:
            return {"anomaly_scores": [], "anomaly_nodes": [], "recon_error": 0.0,
                    "cls_probability": [], "graph_score": 0.0}
        x, edge_index, edge_attr = pyg_data
        return self._gnn_detector.detect(
            x, edge_index, edge_attr=edge_attr, topology=obs.get("_topology"))

    def _combine_scores(self, rule_result, gnn_result, temporal_result,
                        message_result, agent_ids, semantic_rule_result=None):
        scores = {}
        rule_scores = rule_result.get("scores", {})
        temporal_scores = temporal_result.get("temporal_scores", {})
        gnn_scores_list = gnn_result.get("anomaly_scores", [])
        sem_scores = semantic_rule_result.get("agents", {}) if semantic_rule_result else {}

        w_g = self._detect_cfg.get("gnn_weight", 0.35)
        w_r = self._detect_cfg.get("rule_weight", 0.35)
        w_t = self._detect_cfg.get("temporal_weight", 0.15)
        w_s = self._detect_cfg.get("semantic_rule_weight", 0.15)

        for i, aid in enumerate(agent_ids):
            r = rule_scores.get(aid, 0.0)
            t = temporal_scores.get(aid, 0.0)
            g = float(gnn_scores_list[i]) if i < len(gnn_scores_list) else 0.0
            s = sem_scores.get(aid, 0.0)
            weighted = w_r * r + w_g * g + w_t * t + w_s * s
            max_score = max(r, g, t, s)
            scores[aid] = min(max(weighted, max_score * SCORE_BOOST_FACTOR), 1.0)

        for anom in message_result.get("anomalies", []):
            a_type = anom.get("type", "")
            src = anom.get("src", "")
            dst = anom.get("dst", "")
            risk = float(anom.get("risk", DEFAULT_ANOMALY_RISK))
            if src in scores:
                scores[src] = min(max(scores[src], risk), 1.0)
            if dst in scores:
                scores[dst] = min(max(scores[dst], risk * SCORE_BOOST_FACTOR), 1.0)
            if a_type == "cascade_storm" and dst in scores:
                scores[dst] = min(max(scores[dst], risk), 1.0)
            if a_type == "intra_agent_alert" and src in scores:
                scores[src] = min(max(scores[src], risk), 1.0)

        return scores

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
        if self._last_report is None:
            return AnomalyReport()
        return self._last_report

    def reset_state(self):
        self._interaction_graph.clear()
        self._temporal_detector.clear()
        self._message_detector.clear()
        self._logged_supplemental_types.clear()

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
                    content = m.get("content", "")
                    if raw:
                        try:
                            text = base64.b64decode(raw).decode("utf-8")[:MAX_EVENT_TEXT_LEN]
                        except (UnicodeDecodeError, ValueError):
                            text = f"[bin:{raw[:BIN_PREVIEW_LEN]}...]"
                        if not text or not any(c.isalpha() for c in text[:MIN_ALPHA_CHECK]):
                            if content:
                                text = content[:MAX_EVENT_TEXT_LEN]
                            else:
                                text = (raw[:RAW_PREVIEW_LEN] + "...") if raw else "..."
                    elif content:
                        text = content[:MAX_EVENT_TEXT_LEN]
                    else:
                        text = "..."
                except Exception:
                    logger.exception("decode msg data")
                    text = (raw[:RAW_PREVIEW_LEN] + "...") if raw else "..."
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
                    logger.exception("decode message data for %s", agent_id)
                    text = ""
                if len(text) > MIN_SEMANTIC_TEXT_LEN:
                    return {
                        "sender": agent_id,
                        "receiver": m.get("dst", "?"),
                        "content": text[:MAX_SEMANTIC_CONTENT_LEN],
                    }
        return {}

    _ROLE_DUTY = {
        "Supervisor": "delegate tasks to workers",
        "Worker": "execute assigned tasks",
        "Peer": "collaborate to solve problems",
    }

    def _derive_roles(self, obs: dict, agent_ids: list,
                      interactions: list) -> tuple:
        roles = {}
        explicit = obs.get("_roles")
        if isinstance(explicit, dict) and explicit:
            for aid in agent_ids:
                roles[aid] = str(explicit.get(aid, ROLE_UNKNOWN)).capitalize()
        else:
            topo = obs.get("_topology", "unknown")
            if topo == "hierarchical":
                out_targets = {aid: set() for aid in agent_ids}
                for it in interactions:
                    src, dst = it.get("src"), it.get("dst")
                    if src in out_targets and dst:
                        out_targets[src].add(dst)
                sup = max(agent_ids,
                          key=lambda a: (len(out_targets[a]),
                                         -agent_ids.index(a))) if agent_ids else None
                for aid in agent_ids:
                    roles[aid] = "Supervisor" if aid == sup else "Worker"
            elif topo in ("peer-to-peer", "chain", "tree", "ring",
                          "scale_free", "random"):
                for aid in agent_ids:
                    roles[aid] = "Peer"
            else:
                for aid in agent_ids:
                    roles[aid] = ROLE_UNKNOWN
        resp = {}
        for aid in agent_ids:
            duty = self._ROLE_DUTY.get(roles.get(aid, ""), "")
            if duty:
                resp[roles[aid]] = duty
        return roles, resp

    def _build_edge_rows(self, obs: dict, agent_ids: list) -> list:
        from collections import defaultdict
        agg = defaultdict(lambda: {"total": 0, "types": {},
                                   "weight": 0.0, "data_size": 0})

        def merge(src, dst, etype, weight, count, data_size):
            if src not in agent_ids:
                return
            a = agg[(src, dst)]
            n = max(1, int(count or 0))
            a["total"] += n
            a["types"][etype or "message"] = \
                a["types"].get(etype or "message", 0) + n
            if weight:
                a["weight"] = max(a["weight"], float(weight))
            a["data_size"] += int(data_size or 0)

        for it in obs.get("interactions", []):
            merge(it.get("src"), it.get("dst"), it.get("type"),
                  it.get("weight"), it.get("msg_count"),
                  it.get("data_size"))
        if not agg:
            for m in obs.get("messages", []):
                merge(m.get("src"), m.get("dst"), m.get("msg_type", "message"),
                      0.5, 1, m.get("data_size"))
        rows = []
        for (s, d), a in sorted(agg.items()):
            dom_type = max(a["types"], key=lambda t: a["types"][t])
            rows.append({"src": s, "dst": d, "etype": dom_type,
                         "weight": a["weight"], "count": a["total"],
                         "data_size": a["data_size"]})
        return rows

    def _clip(self, s: str) -> str:
        if len(s) <= VIEW_LINE_MAX:
            return s
        return s[:VIEW_LINE_MAX - 3] + "..."

    def _render_ascii_view(self, agent_ids: list, roles: dict,
                           edge_rows: list) -> str:
        from collections import defaultdict
        by_src = defaultdict(list)
        for r in edge_rows:
            by_src[r["src"]].append(r)
        lines = []
        for aid in agent_ids:
            role = roles.get(aid, ROLE_UNKNOWN)
            duty = self._ROLE_DUTY.get(role, "")
            node_label = f"[{aid}] {role}"
            if duty:
                node_label += f" — {duty}"
            lines.append(self._clip(node_label))
            edges = by_src.get(aid, [])
            for i, e in enumerate(edges):
                branch = "└─" if i == len(edges) - 1 else "├─"
                el = (f"{branch}({e['etype']} w={e['weight']:.2f} "
                      f"x{e['count']})─> [{e['dst']}]")
                lines.append(" " + self._clip(el))
        return "\n".join(lines)

    def _format_edge_list(self, edge_rows: list, roles: dict) -> list:
        if not edge_rows:
            return ["(no edges)"]
        lines = []
        shown = min(len(edge_rows), VIEW_EDGE_LIST_LIMIT)
        for e in edge_rows[:shown]:
            src_role = roles.get(e["src"], "")
            dst_role = roles.get(e["dst"], "")
            src_lbl = f"{e['src']}({src_role})" if src_role else e["src"]
            dst_lbl = f"{e['dst']}({dst_role})" if dst_role else e["dst"]
            line = (f"{src_lbl} -({e['etype']} w={e['weight']:.2f} "
                    f"x{e['count']})-> {dst_lbl}")
            lines.append(self._clip(line))
        if len(edge_rows) > shown:
            lines.append(f"... (+{len(edge_rows) - shown} more edges)")
        return lines

    def _analyze_view(self, obs: dict, atype: str) -> dict:
        agents = obs.get("agents", {})
        n = len(agents)
        interactions = obs.get("interactions", [])
        m = len(interactions)
        topo = obs.get("_topology", "unknown")
        agent_list = sorted(agents.keys())
        agents_str = ", ".join(agent_list[:MAX_AGENTS_TO_LIST])
        if n > MAX_AGENTS_TO_LIST:
            agents_str += f" ...(+{n-MAX_AGENTS_TO_LIST})"

        roles, resp = self._derive_roles(obs, agent_list, interactions)
        edge_rows = self._build_edge_rows(obs, agent_list)
        edge_lines = self._format_edge_list(edge_rows, roles)

        use_ascii = (0 < n <= VIEW_SMALL_MAX_AGENTS
                     and m <= VIEW_SMALL_MAX_EDGES)
        ascii_view = (self._render_ascii_view(agent_list, roles, edge_rows)
                      if use_ascii else None)

        return {
            "topology": topo,
            "agents": n,
            "edges": m,
            "agent_list": agents_str,
            "roles": roles,
            "responsibilities": resp,
            "edge_rows": edge_rows,
            "ascii": ascii_view,
            "edge_lines": edge_lines,
        }

    def _format_anomaly_log(self, report, obs: dict) -> str:
        if not report.anomalous_nodes:
            return ""

        lines = []
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        agent_ids = list(obs.get("agents", {}).keys())
        evidence = {}
        try:
            evidence = self._semantic_rule_checker.get_evidence(obs)
        except Exception:
            logger.exception("get_evidence failed")

        sem_types = report.semantic_result.get("anomaly_types", []) if report.semantic_result else []
        obs_type = obs.get("_anomaly_type", "") if isinstance(obs, dict) else ""
        first_type = obs_type if obs_type and obs_type != "normal" else (sem_types[0] if sem_types else "unknown")
        other_types = [t for t in sem_types if t != first_type]

        seen = set()
        type_count = {}
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
            severity = "HIGH" if risk >= SEVERITY_HIGH_THRESHOLD else ("MEDIUM" if risk >= SEVERITY_MEDIUM_THRESHOLD
                                                                         else "LOW")

            group_key = (atype, module, severity)
            type_count[group_key] = type_count.get(group_key, 0) + 1
            if type_count[group_key] > MAX_SAME_TYPE_ENTRIES:
                dup_count += 1
                continue

            ev = evidence.get(aid, {}).get(atype, {})
            try:
                if ev:
                    cause = self._semantic_rule_checker.get_root_cause(atype, ev)
                else:
                    info = obs.get("agents", {}).get(aid, {})
                    if atype == "resource" and info:
                        ev = {"cpu": info.get("cpu_usage", 0), "memory": info.get("memory_usage", 0)}
                        cause = self._semantic_rule_checker.get_root_cause(atype, ev)
                    elif atype == "security" and info:
                        ev = {"shell_exec": info.get("shell_exec_count", 0), "sensitive_file": info.get("sensitive_file_count", 0)}
                        cause = self._semantic_rule_checker.get_root_cause(atype, ev)
                    else:
                        cause = f"Anomaly type '{atype}' detected on {aid}"
            except Exception:
                logger.exception("get_root_cause failed for %s/%s", aid, atype)
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
            lines.append(f"  ... and {dup_count} additional alerts suppressed")

        # Supplementary entries for non-dominant detected types
        for atype in other_types:
            if atype in self._logged_supplemental_types:
                continue
            self._logged_supplemental_types.add(atype)
            module = self._classify_module(atype)
            is_sem = atype in self._SEMANTIC_TYPES
            severity = "HIGH"
            cause = f"Anomaly type '{atype}' detected in observation"
            self._write_entry(lines, module, atype, severity, SUPPLEMENTAL_SEVERITY_RISK,
                              "unknown", cause, obs, agent_ids, ts, is_sem)

        log_text = "\n".join(lines)
        return log_text

    @property
    def interaction_graph(self):
        return self._interaction_graph

    def clear(self):
        self._interaction_graph.clear()
        self._temporal_detector.clear()
        self._intervention.clear()
        self._history.clear()
        self._last_report = None

    def _write_entry(self, lines, module, atype, severity, risk, aid,
                     cause, obs, agent_ids, ts, is_sem):
        lines.append("=" * LINE_SEPARATOR_LEN)
        lines.append(f"[{module}] {atype} ({severity})")
        lines.append(f"risk={risk:.3f}  time={ts}")
        ebpf_pid = obs.get("agents", {}).get(aid, {}).get("_ebpf_pid", "")
        if ebpf_pid:
            lines.append(f"agent={aid}  ebpf={ebpf_pid}")
        lines.append("-" * LINE_SEPARATOR_LEN)
        events = self._collect_events(obs, agent_ids, num=MAX_EVENTS_DISPLAY + 1)
        total_event_count = len(obs.get("messages", [])) + len(obs.get("interactions", []))
        lines.append("[event sequence]")
        for e in events[:MAX_EVENTS_DISPLAY]:
            detail = (e["detail"][:DETAIL_TRUNCATE_LEN] + "...") if len(
                e["detail"]) > DETAIL_TRUNCATE_LEN else e["detail"]
            if detail:
                lines.append(f'  - {e["agent"]}  {e["op"]} -> {e["target"]}  "{detail}"')
            else:
                lines.append(f"  - {e['agent']}  {e['op']} -> {e['target']}")
        total_shown = min(len(events), MAX_EVENTS_DISPLAY)
        if total_event_count > total_shown:
            lines.append(f"  ... (+{total_event_count - total_shown} more events truncated)")
        if is_sem:
            ctx = self._build_semantic_context(obs, atype, aid)
            if ctx:
                lines.append("[semantic association]")
                lines.append(f"  sender: {ctx['sender']}"
                             f" -> receiver: {ctx['receiver']}")
                lines.append(f'  content: "{ctx["content"][:MAX_CONTENT_TRUNCATE_LEN]}"')
        lines.append("[root cause]")
        lines.append(f"  {cause}")
        view = self._analyze_view(obs, atype)
        lines.append("[view]")
        lines.append(f"  topology={view['topology']}"
                     f"  agents={view['agents']}"
                     f"  edges={view['edges']}")
        if view['agent_list']:
            lines.append(f"  agents: {view['agent_list']}")
        roles = view.get("roles") or {}
        if roles:
            role_parts = [f"{a}={roles[a]}" for a in sorted(roles)]
            if len(role_parts) > MAX_AGENTS_TO_LIST:
                role_parts = role_parts[:MAX_AGENTS_TO_LIST] + ["..."]
            lines.append("  roles: " + ", ".join(role_parts))
        resp = view.get("responsibilities") or {}
        if resp:
            resp_parts = [f"{r}={d}" for r, d in resp.items() if d]
            if resp_parts:
                lines.append("  responsibilities: "
                             + "; ".join(resp_parts))
        ascii_view = view.get("ascii")
        if ascii_view:
            for ln in ascii_view.split("\n"):
                lines.append("  " + ln)
        lines.append("  edges:")
        for ln in view.get("edge_lines", []):
            lines.append("  " + ln)
        lines.append("=" * LINE_SEPARATOR_LEN)
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
