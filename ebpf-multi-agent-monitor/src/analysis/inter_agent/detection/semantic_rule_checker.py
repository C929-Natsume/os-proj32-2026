"""Semantic anomaly rule checker — 11 MAST Section 2+3 types via metric/message patterns.

No LLM API needed. Each rule is a pure structural check (O(1) per observation).
Scores are 0.0-1.0 indicating how strongly the rule matches.
Thresholds calibrated against data: normal metric ranges from val_labeled.json.
"""

import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class SemanticRuleChecker:
    """Rule-based semantic anomaly detector covering all 11 MAST taxonomy types.

    Rules derived from metric signatures in ``autogen_scenarios.py``.
    Thresholds calibrated: every rule fires ONLY outside normal metric ranges
    (verified against val_labeled.json normal-data distributions).
    """

    @staticmethod
    def _rule_stale_state(agents: dict, messages: list, interactions: list,
                           agent_ids: List[str]) -> Dict[str, float]:
        """fs_unlink>=3 AND message suggests data is unchanged/cached/stable."""
        import base64
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            fs_unlink = info.get("fs_unlink_count", 0)
            if fs_unlink < 3:
                continue
            # Check if agent's messages suggest unchanged/cached state
            sem_hint = False
            stale_keywords = ["unchanged", "cached", "not modified",
                              "no change", "still the same", "data is stable"]
            for m in messages:
                if m.get("src") == aid:
                    try:
                        raw = m.get("data", "")
                        text = base64.b64decode(raw).decode("utf-8", errors="replace").lower()
                    except Exception:
                        text = ""
                    for kw in stale_keywords:
                        if kw in text:
                            sem_hint = True
                            break
                    if sem_hint:
                        break
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
        """Reply timestamp < request timestamp."""
        scores = {}
        msgs = [m for m in messages if m.get("src") in agent_ids]
        for i in range(len(msgs) - 1):
            t1 = msgs[i].get("timestamp_ns", 0)
            t2 = msgs[i + 1].get("timestamp_ns", 0)
            if t1 > t2 and t1 > 0 and t2 > 0:
                scores[msgs[i].get("src", "")] = 0.6
                scores[msgs[i + 1].get("src", "")] = 0.6
        return scores

    @staticmethod
    def _rule_timeout_retry(agents: dict, messages: list, interactions: list,
                             agent_ids: List[str]) -> Dict[str, float]:
        """api>30 or fs_write>25 AND message mentions retry/timeout."""
        import base64
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            api = info.get("api_call_count", 0)
            fs_write = info.get("fs_write_count", 0)
            metric_hit = api > 30 or fs_write > 25
            if not metric_hit:
                continue
            sem_hint = False
            retry_keywords = ["retry", "timeout", "again", "re-send", "repeating"]
            for m in messages:
                if m.get("src") == aid:
                    try:
                        raw = m.get("data", "")
                        text = base64.b64decode(raw).decode("utf-8", errors="replace").lower()
                    except Exception:
                        text = ""
                    for kw in retry_keywords:
                        if kw in text:
                            sem_hint = True
                            break
                    if sem_hint:
                        break
            if sem_hint:
                if api > 30:
                    scores[aid] = min(1.0, 0.70 + (api - 30) / 50)
                else:
                    scores[aid] = min(1.0, 0.70 + (fs_write - 25) / 20)
            else:
                scores[aid] = min(0.70, 0.50 + (api - 30) / 100 + (fs_write - 25) / 50)
        return scores

    @staticmethod
    def _rule_ignore_input(agents: dict, messages: list, interactions: list,
                            agent_ids: List[str]) -> Dict[str, float]:
        """msg_received >= msg_sent+1 AND has incoming message."""
        scores = {}
        targeted = set()
        for m in messages:
            dst = m.get("dst", "")
            if dst in agent_ids:
                targeted.add(dst)
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

    # ── Rule registry ──

    RULES: List[Tuple[str, callable]] = [
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

        all_agent_scores: Dict[str, float] = {}
        types_found: Dict[str, Dict[str, float]] = {}

        for type_name, rule_fn in self.RULES:
            try:
                per_agent = rule_fn(agents_data, messages, interactions, agent_ids)
            except Exception as e:
                logger.warning("Rule %s raised: %s", type_name, e)
                per_agent = {}
            for aid, risk in per_agent.items():
                if risk <= 0.0:
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
        evidence = {}
        for type_name, rule_fn in self.RULES:
            try:
                per_agent = rule_fn(agents_data, messages, interactions, agent_ids)
            except Exception as e:
                logger.debug("get_evidence rule %s: %s", type_name, e)
                per_agent = {}
            for aid, risk in per_agent.items():
                if risk <= 0.0:
                    continue
                entry = evidence.setdefault(aid, {})
                info = agents_data.get(aid, {})
                if type_name == "stale_state":
                    entry[type_name] = {
                        "fs_unlink": info.get("fs_unlink_count", 0),
                        "fs_write": info.get("fs_write_count", 0),
                        "risk": round(risk, 3),
                    }
                elif type_name == "state_conflict":
                    entry[type_name] = {
                        "fs_write": info.get("fs_write_count", 0),
                        "api_call": info.get("api_call_count", 0),
                        "conflict_with": [a for a in agent_ids if a != aid
                                          and agents.get(a, {}).get("fs_write_count", 0) > 20],
                        "risk": round(risk, 3),
                    }
                elif type_name == "partial_visibility":
                    entry[type_name] = {
                        "fs_open": info.get("fs_open_count", 0),
                        "unique_files": info.get("unique_files_count", 0),
                        "risk": round(risk, 3),
                    }
                elif type_name == "message_disorder":
                    entry[type_name] = {
                        "messages": len([m for m in messages if m.get("src") == aid]),
                        "timestamps": [m.get("timestamp_ns", 0) for m in messages
                                      if m.get("src") in agent_ids][:4],
                        "risk": round(risk, 3),
                    }
                elif type_name == "timeout_retry":
                    entry[type_name] = {
                        "api_call": info.get("api_call_count", 0),
                        "fs_write": info.get("fs_write_count", 0),
                        "fs_read": info.get("fs_read_count", 0),
                        "risk": round(risk, 3),
                    }
                elif type_name == "ignore_input":
                    src_list = [m.get("src", "") for m in messages
                               if m.get("dst") == aid]
                    entry[type_name] = {
                        "msg_received": info.get("msg_received", 0),
                        "msg_sent": info.get("msg_sent", 0),
                        "from_agents": src_list,
                        "risk": round(risk, 3),
                    }
                elif type_name == "reasoning_action_mismatch":
                    entry[type_name] = {
                        "shell_exec": info.get("shell_exec_count", 0),
                        "sensitive_file": info.get("sensitive_file_count", 0),
                        "proc_exec": info.get("proc_exec_count", 0),
                        "risk": round(risk, 3),
                    }
                elif type_name == "wrong_assumption":
                    entry[type_name] = {
                        "net_connect": info.get("net_connect_count", 0),
                        "net_send": info.get("net_send_count", 0),
                        "api_call": info.get("api_call_count", 0),
                        "risk": round(risk, 3),
                    }
                elif type_name == "task_derailment":
                    entry[type_name] = {
                        "proc_exec": info.get("proc_exec_count", 0),
                        "api_call": info.get("api_call_count", 0),
                        "proc_fork": info.get("proc_fork_count", 0),
                        "risk": round(risk, 3),
                    }
                elif type_name == "concealment":
                    entry[type_name] = {
                        "cpu": info.get("cpu_usage", 0),
                        "memory": info.get("memory_usage", 0),
                        "proc_fork": info.get("proc_fork_count", 0),
                        "shell_exec": info.get("shell_exec_count", 0),
                        "risk": round(risk, 3),
                    }
                elif type_name == "premature_convergence":
                    entry[type_name] = {
                        "api_call": info.get("api_call_count", 0),
                        "fs_read": info.get("fs_read_count", 0),
                        "messages": len(messages),
                        "risk": round(risk, 3),
                    }
        return evidence

    ROOT_CAUSE_MAP = {
        "stale_state": "fs_unlink={fs_unlink} file deletions detected while agent was active — may indicate operating on outdated file state",
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
    }

    def get_root_cause(self, anom_type: str, evidence: dict) -> str:
        """Return human-readable root cause description."""
        if anom_type not in self.ROOT_CAUSE_MAP:
            return f"Anomaly type '{anom_type}' detected by rule system"
        template = self.ROOT_CAUSE_MAP[anom_type]
        try:
            return template.format(**evidence)
        except KeyError:
            return template

    @property
    def is_enabled(self) -> bool:
        return True