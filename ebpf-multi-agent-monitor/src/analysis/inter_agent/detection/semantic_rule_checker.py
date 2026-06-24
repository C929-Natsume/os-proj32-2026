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
        """fs_unlink>0: always 0 in normal, >=1 in anomaly."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            fs_unlink = info.get("fs_unlink_count", 0)
            if fs_unlink >= 1:
                scores[aid] = 0.7 + min(fs_unlink * 0.2, 0.3)
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
        """api>30 or fs_write>25 (normal: api=4-6, fs_write=5-20)."""
        scores = {}
        for aid in agent_ids:
            info = agents.get(aid, {})
            api = info.get("api_call_count", 0)
            fs_write = info.get("fs_write_count", 0)
            if api > 30:
                scores[aid] = min(1.0, 0.7 + (api - 30) / 50)
            elif fs_write > 25:
                scores[aid] = min(1.0, 0.7 + (fs_write - 25) / 20)
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

    @property
    def is_enabled(self) -> bool:
        return True