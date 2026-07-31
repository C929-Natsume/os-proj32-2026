"""Semantic anomaly rule checker — 11 MAST Section 2+3 types via metric/message patterns.
No LLM API needed. Each rule is a purely structural check (O(1) per observation).
"""

import base64
import logging
from typing import Dict, List, Tuple, Callable

logger = logging.getLogger(__name__)


def _decode_msg_text(raw: str) -> str:
    """Decode base64 message data, returning lowercased text or empty on failure."""
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace").lower()
    except Exception:
        return ""


def _has_keyword_in_messages(messages: list, aid: str, keywords: list) -> bool:
    """Check if any message from ''aid'' contains one of ''keywords''."""
    for m in messages:
        if m.get("src") == aid:
            raw = m.get("data", "")
            text = _decode_msg_text(raw)
            for kw in keywords:
                if kw in text:
                    return True
    return False


class SemanticRuleChecker:
    """Rule-based semantic anomaly detector covering all 11 MAST taxonomy types.

    Rules derived from metric signatures in ``autogen_scenarios.py``.
    Thresholds calibrated: every rule fires ONLY outside normal metric ranges
    (verified against val_labeled.json normal-data distributions).
    """

    @staticmethod
    def _rule_stale_state(agents: dict, messages: list, interactions: list,
                           agent_ids: List[str]) -> Dict[str, float]:
        """fs_unlink>=2 or zero-activity agent (cpu=0, mem=0, api=0)."""
        scores = {}
        stale_keywords = ["unchanged", "cached", "not modified",
                          "no change", "still the same", "data is stable"]
        for aid in agent_ids:
            info = agents.get(aid, {})
            fs_unlink = info.get("fs_unlink_count", 0)
            cpu = info.get("cpu_usage", 0.5)
            mem = info.get("memory_usage", 0.5)
            api = info.get("api_call_count", 5)
            if cpu == 0 and mem == 0 and api == 0:
                scores[aid] = 0.55
                continue
            if fs_unlink < 2:
                continue
            sem_hint = _has_keyword_in_messages(messages, aid, stale_keywords)
            if sem_hint:
                scores[aid] = 0.70 + min(fs_unlink * 0.03, 0.25)
            else:
                scores[aid] = 0.55 + min(fs_unlink * 0.02, 0.20)
        return scores

    @staticmethod
    def _rule_state_conflict(agents: dict, messages: list, interactions: list,
                              agent_ids: List[str]) -> Dict[str, float]:
        """2 agents with fs_write>20 (normal max=20)."""
        agents_high = [aid for aid in agent_ids
                       if agents.get(aid, {}).get("fs_write_count", 0) > 20]
        if len(agents_high) >= 2:
            return {aid: 0.8 for aid in agents_high}
        return {}

    @staticmethod
    def _rule_partial_visibility(agents: dict, messages: list, interactions: list,
                                  agent_ids: List[str]) -> Dict[str, float]:
        """fs_open<=2 AND unique<=3 (normal: fs_open=2-8, unique=2-8)."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            fs_open = info.get("fs_open_count", 0)
            unique = info.get("unique_files_count", 0)
            if fs_open <= 2 and unique <= 3:
                scores[aid] = 0.7
        return scores

    @staticmethod
    def _rule_message_disorder(agents: dict, messages: list, interactions: list,
                                 agent_ids: List[str]) -> Dict[str, float]:
        """Reply timestamp < request timestamp, or identical timestamps with different content."""
        scores = {}
        msgs = [m for m in messages if m.get("src") in agent_ids]
        for i in range(len(msgs) - 1):
            t1 = msgs[i].get("timestamp_ns", 0)
            t2 = msgs[i + 1].get("timestamp_ns", 0)
            # Strict inversion: later message has earlier timestamp
            if t1 > t2 and t1 > 0 and t2 > 0:
                scores[msgs[i].get("src", "")] = 0.6
                scores[msgs[i + 1].get("src", "")] = 0.6
            # Same timestamp but different content suggests incorrect ordering
            elif t1 == t2 and t1 > 0:
                c1 = msgs[i].get("content", "")
                c2 = msgs[i + 1].get("content", "")
                if c1 != c2:
                    scores[msgs[i].get("src", "")] = 0.5
                    scores[msgs[i + 1].get("src", "")] = 0.5
        return scores

    @staticmethod
    def _rule_timeout_retry(agents: dict, messages: list, interactions: list,
                              agent_ids: List[str]) -> Dict[str, float]:
        """api>30 or fs_write>25 (original), or net_send>=30 + message mentions retry/timeout."""
        scores = {}
        retry_keywords = ["retry", "timeout", "again", "re-send", "repeating"]
        for aid in agent_ids:
            info = agents.get(aid, {})
            api = info.get("api_call_count", 0)
            fs_write = info.get("fs_write_count", 0)
            net_send = info.get("net_send_count", 0)
            metric_hit = api > 30 or fs_write > 25 or net_send >= 30
            if not metric_hit:
                continue
            sem_hint = _has_keyword_in_messages(messages, aid, retry_keywords)
            if sem_hint:
                score_val = 0.70
                if api > 30:
                    score_val += (api - 30) / 50
                if fs_write > 25:
                    score_val += (fs_write - 25) / 40
                scores[aid] = min(1.0, score_val)
            else:
                score_val = 0.55 if net_send >= 30 else 0.50
                if api > 30:
                    score_val += (api - 30) / 100
                if fs_write > 25:
                    score_val += (fs_write - 25) / 50
                scores[aid] = min(0.70, score_val)
        return scores

    @staticmethod
    def _rule_ignore_input(agents: dict, messages: list, interactions: list,
                             agent_ids: List[str]) -> Dict[str, float]:
        """msg_received >= msg_sent+1 AND has incoming message (or all agents if no messages)."""
        scores = {}
        targeted = set()
        for m in messages:
            dst = m.get("dst", "")
            if dst in agent_ids:
                targeted.add(dst)
        if not targeted:
            targeted = set(agent_ids)
        for aid in targeted:
            info = agents.get(aid, {})
            received = info.get("msg_received", 0)
            sent = info.get("msg_sent", 0)
            if received >= sent + 1:
                scores[aid] = 0.7
        return scores

    @staticmethod
    def _rule_reasoning_action_mismatch(agents: dict, messages: list,
                                         interactions: list,
                                         agent_ids: List[str]) -> Dict[str, float]:
        """shell_exec>0 or sensitive_file>0 (both ALWAYS 0 in normal)."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            shell = info.get("shell_exec_count", 0)
            sensitive = info.get("sensitive_file_count", 0)
            if shell > 0 or sensitive > 0:
                scores[aid] = min(1.0, 0.7 + shell * 0.1 + sensitive * 0.15)
        return scores

    @staticmethod
    def _rule_wrong_assumption(agents: dict, messages: list, interactions: list,
                                agent_ids: List[str]) -> Dict[str, float]:
        """net_connect=0 AND net_send=0 (normal: net_c=1-5, net_s=16-29 — ALWAYS non-zero)."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            net_connect = info.get("net_connect_count", 0)
            net_send = info.get("net_send_count", 0)
            api = info.get("api_call_count", 0)
            if net_connect == 0 and net_send == 0:
                scores[aid] = 0.8
        return scores

    @staticmethod
    def _rule_task_derailment(agents: dict, messages: list, interactions: list,
                               agent_ids: List[str]) -> Dict[str, float]:
        """proc_exec>=4 AND api>=20 (normal: proc=1, api=4-6)."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            proc_exec = info.get("proc_exec_count", 0)
            api = info.get("api_call_count", 0)
            if proc_exec >= 4 and api >= 20:
                scores[aid] = min(1.0, 0.7 + (proc_exec - 4) * 0.05 + (api - 20) * 0.005)
        return scores

    @staticmethod
    def _rule_concealment(agents: dict, messages: list, interactions: list,
                           agent_ids: List[str]) -> Dict[str, float]:
        """cpu>0.85 AND mem>0.85 (normal: cpu=0.3-0.6, mem=0.3-0.5)."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            cpu = info.get("cpu_usage", 0)
            mem = info.get("memory_usage", 0)
            if cpu > 0.85 and mem > 0.85:
                scores[aid] = min(1.0, 0.7 + (cpu - 0.85) * 2 + (mem - 0.85) * 2)
        return scores

    @staticmethod
    def _rule_premature_convergence(agents: dict, messages: list,
                                     interactions: list,
                                     agent_ids: List[str]) -> Dict[str, float]:
        """api<=3 AND fs_read<=5 (normal: api=4-6, fs_read=10-40)."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            api = info.get("api_call_count", 0)
            fs_read = info.get("fs_read_count", 0)
            if api <= 3 and fs_read <= 5:
                scores[aid] = 0.55
        return scores

    @staticmethod
    def _rule_supervisor_bypass(agents: dict, messages: list, interactions: list,
                                  agent_ids: List[str],
                                  topology: str = "unknown") -> Dict[str, float]:
        """Agent-agent bypass edges (type=bypass) between worker agents."""
        if topology != "hierarchical":
            return {}
        aid_set = set(agent_ids)
        for it in interactions:
            src = it.get("src", "")
            dst = it.get("dst", "")
            if src in aid_set and dst in aid_set and it.get("type") == "bypass":
                return {agent_ids[0]: 0.8}
        return {}

    @staticmethod
    def _rule_group_split(agents: dict, messages: list, interactions: list,
                           agent_ids: List[str]) -> Dict[str, float]:
        """Cross-group agent-to-agent edges with low weight (group fragmentation)."""
        if len(agent_ids) < 2:
            return {}
        mid = max(1, len(agent_ids) // 2)
        group_a = set(agent_ids[:mid])
        group_b = set(agent_ids[mid:])
        cross_count = 0
        cross_weight_sum = 0.0
        for it in interactions:
            src = it.get("src", "")
            dst = it.get("dst", "")
            if (src in group_a and dst in group_b) or (src in group_b and dst in group_a):
                cross_count += 1
                cross_weight_sum += it.get("weight", 0.5)
        min_cross = 3 if len(agent_ids) >= 6 else 1
        if cross_count < min_cross:
            return {}
        avg_w = cross_weight_sum / cross_count
        if avg_w < 0.3:
            return {agent_ids[0]: min(0.70, 0.40 + 0.04 * cross_count),
                    agent_ids[mid]: min(0.70, 0.40 + 0.04 * cross_count)}
        return {}

    @staticmethod
    def _rule_flood_from_single(agents: dict, messages: list, interactions: list,
                                 agent_ids: List[str]) -> Dict[str, float]:
        """Single source sends to 3+ distinct targets in interactions or messages."""
        src_dsts = {}
        for it in interactions:
            src = it.get("src", "")
            dst = it.get("dst", "")
            if src in agent_ids:
                src_dsts.setdefault(src, set()).add(dst)
        for m in messages:
            src = m.get("src", "")
            dst = m.get("dst", "")
            if src in agent_ids:
                src_dsts.setdefault(src, set()).add(dst)
        for src, dsts in src_dsts.items():
            threshold = 3 if len(agent_ids) >= 6 else (2 if len(agent_ids) >= 3 else 99)
            if len(dsts) >= threshold:
                return {src: min(0.75, 0.45 + 0.06 * len(dsts))}
        return {}

    @staticmethod
    def _rule_message_storm(agents: dict, messages: list, interactions: list,
                             agent_ids: List[str]) -> Dict[str, float]:
        """Agent with high msg_received and many incoming interactions."""
        incoming = {}
        for it in interactions:
            dst = it.get("dst", "")
            if dst in agent_ids:
                incoming[dst] = incoming.get(dst, 0) + 1
        for aid in agent_ids:
            info = agents.get(aid, {})
            recv = info.get("msg_received", 0)
            inc = incoming.get(aid, 0)
            if recv >= 30 and inc >= 5:
                score = min(0.80, 0.45 + 0.01 * recv)
                return {aid: score}
        return {}

    # ── Rule registry ──

    RULES: List[Tuple[str, Callable[..., Dict[str, float]]]] = [
        ("stale_state",             _rule_stale_state.__func__),
        ("state_conflict",          _rule_state_conflict.__func__),
        ("partial_visibility",      _rule_partial_visibility.__func__),
        ("message_disorder",        _rule_message_disorder.__func__),
        ("timeout_retry",           _rule_timeout_retry.__func__),
        ("ignore_input",            _rule_ignore_input.__func__),
        ("reasoning_action_mismatch", _rule_reasoning_action_mismatch.__func__),
        ("wrong_assumption",        _rule_wrong_assumption.__func__),
        ("task_derailment",         _rule_task_derailment.__func__),
        ("concealment",             _rule_concealment.__func__),
        ("premature_convergence",   _rule_premature_convergence.__func__),
        ("supervisor_bypass",       _rule_supervisor_bypass.__func__),
        ("group_split",             _rule_group_split.__func__),
        ("flood_from_single",       _rule_flood_from_single.__func__),
        ("message_storm",           _rule_message_storm.__func__),
    ]

    # ── Public API ──

    def __init__(self, risk_threshold: float = 0.5):
        self._risk_threshold = risk_threshold

    def check(self, obs: dict) -> dict:
        """Run all 11 rules against a single observation."""
        agents_data = obs.get("agents", {})
        agent_ids = list(agents_data.keys())
        messages = obs.get("messages", [])
        interactions = obs.get("interactions", [])
        topology = obs.get("_topology", "unknown")

        all_agent_scores: Dict[str, float] = {}
        types_found: Dict[str, Dict[str, float]] = {}

        for type_name, rule_fn in self.RULES:
            try:
                if type_name == "supervisor_bypass":
                    per_agent = rule_fn(agents_data, messages, interactions,
                                        agent_ids, topology=topology)
                else:
                    per_agent = rule_fn(agents_data, messages, interactions, agent_ids)
            except Exception as e:
                logger.warning("Rule %s raised: %s", type_name, e)
                per_agent = {}
            for aid, risk in per_agent.items():
                if risk <= 0.0 or aid not in agent_ids:
                    continue
                all_agent_scores[aid] = max(all_agent_scores.get(aid, 0.0), risk)
                types_found.setdefault(type_name, {})[aid] = risk

        overall_risk = max(all_agent_scores.values()) if all_agent_scores else 0.0
        anomaly_types = list(types_found.keys())

        return {
            "agents": all_agent_scores,
            "types": types_found,
            "overall_risk": overall_risk,
            "anomaly_types": anomaly_types,
        }

    def is_anomalous(self, obs: dict) -> bool:
        return self.check(obs)["overall_risk"] >= self._risk_threshold

    def get_evidence(self, obs: dict) -> dict:
        """Return per-agent evidence for each triggered rule."""
        agents_data = obs.get("agents", {})
        agent_ids = list(agents_data.keys())[:16]
        messages = obs.get("messages", [])
        interactions = obs.get("interactions", [])
        topology = obs.get("_topology", "unknown")
        evidence = {}

        # Data-driven evidence field extractors keyed by type_name
        agent_set = set(agent_ids)
        evidence_spec = {
            "stale_state": lambda info: {
                "fs_unlink": info.get("fs_unlink_count", 0),
                "fs_write": info.get("fs_write_count", 0),
                "cpu": info.get("cpu_usage", 0.5),
                "memory": info.get("memory_usage", 0.5),
                "api_call": info.get("api_call_count", 5),
                "mode": ("zero_activity" if (info.get("cpu_usage", 0.5) == 0
                          and info.get("memory_usage", 0.5) == 0
                          and info.get("api_call_count", 5) == 0)
                         else "file_deletion")},
            "state_conflict": lambda info: {
                "fs_write": info.get("fs_write_count", 0),
                "api_call": info.get("api_call_count", 0),
                "conflict_with": [a for a in agent_ids if a != aid
                                  and agents_data.get(a, {}).get("fs_write_count", 0) > 20]},
            "partial_visibility": lambda info: {
                "fs_open": info.get("fs_open_count", 0),
                "unique_files": info.get("unique_files_count", 0)},
            "message_disorder": lambda info: {
                "messages": len([m for m in messages if m.get("src") == aid]),
                "timestamps": [m.get("timestamp_ns", 0) for m in messages
                              if m.get("src") in agent_ids][:4]},
            "timeout_retry": lambda info: {
                "api_call": info.get("api_call_count", 0),
                "fs_write": info.get("fs_write_count", 0),
                "fs_read": info.get("fs_read_count", 0)},
            "ignore_input": lambda info: {
                "msg_received": info.get("msg_received", 0),
                "msg_sent": info.get("msg_sent", 0),
                "from_agents": [m.get("src", "") for m in messages if m.get("dst") == aid]},
            "reasoning_action_mismatch": lambda info: {
                "shell_exec": info.get("shell_exec_count", 0),
                "sensitive_file": info.get("sensitive_file_count", 0),
                "proc_exec": info.get("proc_exec_count", 0)},
            "wrong_assumption": lambda info: {
                "net_connect": info.get("net_connect_count", 0),
                "net_send": info.get("net_send_count", 0),
                "api_call": info.get("api_call_count", 0)},
            "task_derailment": lambda info: {
                "proc_exec": info.get("proc_exec_count", 0),
                "api_call": info.get("api_call_count", 0),
                "proc_fork": info.get("proc_fork_count", 0)},
            "concealment": lambda info: {
                "cpu": info.get("cpu_usage", 0),
                "memory": info.get("memory_usage", 0),
                "proc_fork": info.get("proc_fork_count", 0),
                "shell_exec": info.get("shell_exec_count", 0)},
            "premature_convergence": lambda info: {
                "api_call": info.get("api_call_count", 0),
                "fs_read": info.get("fs_read_count", 0),
                "messages": len(messages)},
            "supervisor_bypass": lambda info: {
                "bypass_edges": [{"src": x.get("src"), "dst": x.get("dst"),
                                  "weight": x.get("weight")}
                                for x in interactions
                                if x.get("src") in agent_set and x.get("dst") in agent_set
                                and x.get("type") == "bypass"]},
            "group_split": lambda info: {"interactions": len(interactions)},
            "flood_from_single": lambda info: {"interactions": len(interactions)},
            "message_storm": lambda info: {"msg_received": info.get("msg_received", 0)},
            "resource": lambda info: {
                "cpu": info.get("cpu_usage", 0),
                "memory": info.get("memory_usage", 0)},
            "security": lambda info: {
                "shell_exec": info.get("shell_exec_count", 0),
                "sensitive_file": info.get("sensitive_file_count", 0)},
            "propagation": lambda info: {},
            "frequency_surge": lambda info: {"src": "", "freq": 0},
            "cascade_storm": lambda info: {},
            "data_size_anomaly": lambda info: {"data_size": 0},
            "intra_agent_alert": lambda info: {"src": "", "risk": 0},
        }

        for type_name, rule_fn in self.RULES:
            try:
                if type_name == "supervisor_bypass":
                    per_agent = rule_fn(agents_data, messages, interactions,
                                        agent_ids, topology=topology)
                else:
                    per_agent = rule_fn(agents_data, messages, interactions, agent_ids)
            except Exception as e:
                logger.debug("get_evidence rule %s: %s", type_name, e)
                per_agent = {}
            extract = evidence_spec.get(type_name)
            if extract is None:
                continue
            for aid, risk in per_agent.items():
                if risk <= 0.0:
                    continue
                entry = evidence.setdefault(aid, {})
                info = agents_data.get(aid, {})
                fields = extract(info)
                fields["risk"] = round(risk, 3)
                entry[type_name] = fields
        return evidence

    ROOT_CAUSE_MAP = {
        "stale_state": {
            "zero_activity": "Agent idle (cpu=0, memory=0, api_calls=0) — zero activity, state may be stale",
            "file_deletion": "fs_unlink={fs_unlink} file deletions — may indicate operating on outdated file state",
        },
        "state_conflict": "Agent claimed exclusive access on a shared resource, but another agent also wrote to the same resource concurrently — state inconsistency between agents",
        "partial_visibility": "Agent reported limited file visibility (fs_open={fs_open}, unique_files={unique_files}), but should have had broader access",
        "message_disorder": "Message order violation: a reply timestamp precedes its request timestamp — causal relationship broken",
        "timeout_retry": "Agent triggered excessive retries (api_call={api_call}, fs_write={fs_write}) — possible duplicated operations from timeout handling",
        "ignore_input": "Agent received incoming messages from {from_agents} but did not respond (msg_received={msg_received}, msg_sent={msg_sent}) — input ignored",
        "reasoning_action_mismatch": "Agent claimed safe/benign activity but metrics show shell_exec={shell_exec} and sensitive_file={sensitive_file} — reasoning contradicts actual actions",
        "wrong_assumption": "Agent assumed network connectivity was available but net_connect=0 and net_send=0 — acting on false premise",
        "task_derailment": "Agent deviated from original task: proc_exec={proc_exec} and api_call={api_call} indicate unrelated activity instead of assigned work",
        "concealment": "Agent reported normal operations but cpu={cpu} and memory={memory} are critically high — hiding resource abuse behind benign message content",
        "premature_convergence": "Agents agreed after only {messages} messages with minimal work done (api_call={api_call}, fs_read={fs_read}) — insufficient exploration before convergence",
        "supervisor_bypass": "Workers communicated directly with each other via bypass-type edges instead of routing through the supervisor — supervisor bypass detected",
        "group_split": "Agents split into subgroups with cross-group communication at low weights — group fragmentation detected",
        "flood_from_single": "Single agent sent interactions to 3+ distinct targets — flood from single source detected",
        "message_storm": "Agent received excessive messages (msg_received={msg_received}) — message storm detected",
        "resource": "Agent resource usage critically high (cpu={cpu}, memory={memory}) — resource exhaustion detected",
        "security": "Agent performed security-sensitive operations (shell_exec={shell_exec}, sensitive_file={sensitive_file}) — security anomaly detected",
        "propagation": "Anomaly propagated through agents via interaction chain — propagation path detected",
        "frequency_surge": "Message frequency anomaly from agent — frequency surge detected",
        "cascade_storm": "Cascade storm propagated to multiple agents — cascade anomaly detected",
        "data_size_anomaly": "Message data size anomaly ({data_size} bytes) — exceeds normal threshold",
        "intra_agent_alert": "Intra-agent behavior deviation detected — internal anomaly",
    }

    def get_root_cause(self, anom_type: str, evidence: dict) -> str:
        """Return human-readable root cause description."""
        entry = self.ROOT_CAUSE_MAP.get(anom_type)
        if entry is None:
            return f"Anomaly type '{anom_type}' detected by rule system"
        if isinstance(entry, dict):
            mode = evidence.get("mode", "file_deletion")
            template = entry.get(mode, entry["file_deletion"])
        else:
            template = entry
        try:
            return template.format(**evidence)
        except KeyError:
            return template

    @property
    def is_enabled(self) -> bool:
        return True