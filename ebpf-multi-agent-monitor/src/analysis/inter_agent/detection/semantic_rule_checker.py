"""Semantic anomaly rule checker — 11 MAST Section 2+3 types via metric/message patterns.
No LLM API needed. Each rule is a purely structural check (O(1) per observation).

Supports optional online Bayesian boundary adaptation (see adaptive_bounds.py):
  - adaptive=False (default): byte-identical to the static checker.
  - adaptive=True: rule boundaries follow the drifting normal baseline and
    per-rule Beta posteriors dampen over-firing rules.
"""

import base64
import json
import logging
import os
from typing import Dict, List, Optional

from inter_agent.detection.adaptive_bounds import AdaptiveBoundaryState

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

    # ── adaptive boundary registry ────────────────────────────────────────
    # (rule, metric, anchor, direction). Anchors are the hardcoded values the
    # static checker uses; direction is "upper" (fire when metric exceeds the
    # bound) or "lower" (fire when metric falls below the bound).
    ADAPTIVE_BOUNDS = [
        ("stale_state", "fs_unlink_count", 2, "upper"),
        ("state_conflict", "fs_write_count", 20, "upper"),
        ("partial_visibility", "fs_open_count", 2, "lower"),
        ("partial_visibility", "unique_files_count", 3, "lower"),
        ("timeout_retry", "api_call_count", 30, "upper"),
        ("timeout_retry", "fs_write_count", 25, "upper"),
        ("timeout_retry", "net_send_count", 30, "upper"),
        ("task_derailment", "proc_exec_count", 4, "upper"),
        ("task_derailment", "api_call_count", 20, "upper"),
        ("concealment", "cpu_usage", 0.85, "upper"),
        ("concealment", "memory_usage", 0.85, "upper"),
        ("premature_convergence", "api_call_count", 3, "lower"),
        ("premature_convergence", "fs_read_count", 5, "lower"),
        ("message_storm", "msg_received", 30, "upper"),
    ]

    # (metric -> (init_mean, init_std)) — normal-baseline seed for the online
    # statistics, aligned with SAFE_METRICS / val_labeled normal data.
    ADAPTIVE_SEEDS = {
        "fs_unlink_count": (0.0, 0.5),
        "fs_write_count": (15.0, 6.0),
        "fs_open_count": (30.0, 10.0),
        "unique_files_count": (10.0, 4.0),
        "api_call_count": (15.0, 6.0),
        "net_send_count": (10.0, 4.0),
        "proc_exec_count": (3.0, 1.5),
        "cpu_usage": (0.15, 0.08),
        "memory_usage": (0.25, 0.10),
        "fs_read_count": (40.0, 12.0),
        "msg_received": (6.0, 3.0),
    }

    # ── rules ─────────────────────────────────────────────────────────────

    def _bound(self, rule: str, metric: str, anchor: float, direction: str) -> float:
        """Effective metric boundary for a rule (anchor unless adaptive)."""
        return self._adaptive.bound(rule, metric, anchor, direction)

    def _rule_stale_state(self, agents: dict, messages: list, interactions: list,
                          agent_ids: List[str]) -> Dict[str, float]:
        """fs_unlink>=2 or zero-activity agent (cpu=0, mem=0, api=0)."""
        scores = {}
        stale_keywords = ["unchanged", "cached", "not modified",
                          "no change", "still the same", "data is stable"]
        unlink_th = self._bound("stale_state", "fs_unlink_count", 2, "upper")
        for aid in agent_ids:
            info = agents.get(aid, {})
            fs_unlink = info.get("fs_unlink_count", 0)
            cpu = info.get("cpu_usage", 0.5)
            mem = info.get("memory_usage", 0.5)
            api = info.get("api_call_count", 5)
            if cpu == 0 and mem == 0 and api == 0:
                scores[aid] = 0.55
                continue
            if fs_unlink < unlink_th:
                continue
            sem_hint = _has_keyword_in_messages(messages, aid, stale_keywords)
            if sem_hint:
                scores[aid] = 0.70 + min(fs_unlink * 0.03, 0.25)
            else:
                scores[aid] = 0.55 + min(fs_unlink * 0.02, 0.20)
        return scores

    def _rule_state_conflict(self, agents: dict, messages: list, interactions: list,
                             agent_ids: List[str]) -> Dict[str, float]:
        """2 agents with fs_write>20 (normal max=20)."""
        w_th = self._bound("state_conflict", "fs_write_count", 20, "upper")
        agents_high = [aid for aid in agent_ids
                       if agents.get(aid, {}).get("fs_write_count", 0) > w_th]
        if len(agents_high) >= 2:
            return {aid: 0.8 for aid in agents_high}
        return {}

    def _rule_partial_visibility(self, agents: dict, messages: list, interactions: list,
                                 agent_ids: List[str]) -> Dict[str, float]:
        """fs_open<=2 AND unique<=3 (normal: fs_open=2-8, unique=2-8)."""
        scores = {}
        open_th = self._bound("partial_visibility", "fs_open_count", 2, "lower")
        unique_th = self._bound("partial_visibility", "unique_files_count", 3, "lower")
        for aid in agent_ids:
            info = agents.get(aid, {})
            fs_open = info.get("fs_open_count", 0)
            unique = info.get("unique_files_count", 0)
            if fs_open <= open_th and unique <= unique_th:
                scores[aid] = 0.7
        return scores

    def _rule_message_disorder(self, agents: dict, messages: list, interactions: list,
                               agent_ids: List[str]) -> Dict[str, float]:
        """Reply timestamp < request timestamp, or identical timestamps with different content."""
        scores = {}
        msgs = [m for m in messages if m.get("src") in agent_ids]
        for i in range(len(msgs) - 1):
            t1 = msgs[i].get("timestamp_ns", 0)
            t2 = msgs[i + 1].get("timestamp_ns", 0)
            # Strict inversion: later message has earlier timestamp
            if t1 > t2 and t1 > 0 and t2 > 0:
                scores[msgs[i].get("src", "")] = 0.9
                scores[msgs[i + 1].get("src", "")] = 0.9
            # Same timestamp but different content suggests incorrect ordering
            elif t1 == t2 and t1 > 0:
                c1 = msgs[i].get("content", "")
                c2 = msgs[i + 1].get("content", "")
                if c1 != c2:
                    scores[msgs[i].get("src", "")] = 0.5
                    scores[msgs[i + 1].get("src", "")] = 0.5
        return scores

    def _rule_timeout_retry(self, agents: dict, messages: list, interactions: list,
                            agent_ids: List[str]) -> Dict[str, float]:
        """api>30 or fs_write>25 (original), or net_send>=30 + message mentions retry/timeout."""
        scores = {}
        retry_keywords = ["retry", "timeout", "again", "re-send", "repeating"]
        api_th = self._bound("timeout_retry", "api_call_count", 30, "upper")
        w_th = self._bound("timeout_retry", "fs_write_count", 25, "upper")
        send_th = self._bound("timeout_retry", "net_send_count", 30, "upper")
        for aid in agent_ids:
            info = agents.get(aid, {})
            api = info.get("api_call_count", 0)
            fs_write = info.get("fs_write_count", 0)
            net_send = info.get("net_send_count", 0)
            metric_hit = api > api_th or fs_write > w_th or net_send >= send_th
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

    def _rule_ignore_input(self, agents: dict, messages: list, interactions: list,
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

    def _rule_reasoning_action_mismatch(self, agents: dict, messages: list,
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

    def _rule_wrong_assumption(self, agents: dict, messages: list, interactions: list,
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

    def _rule_task_derailment(self, agents: dict, messages: list, interactions: list,
                              agent_ids: List[str]) -> Dict[str, float]:
        """proc_exec>=4 AND api>=20 (normal: proc=1, api=4-6)."""
        scores = {}
        proc_th = self._bound("task_derailment", "proc_exec_count", 4, "upper")
        api_th = self._bound("task_derailment", "api_call_count", 20, "upper")
        for aid in agent_ids:
            info = agents.get(aid, {})
            proc_exec = info.get("proc_exec_count", 0)
            api = info.get("api_call_count", 0)
            if proc_exec >= proc_th and api >= api_th:
                scores[aid] = min(1.0, 0.7 + (proc_exec - 4) * 0.05 + (api - 20) * 0.005)
        return scores

    def _rule_concealment(self, agents: dict, messages: list, interactions: list,
                          agent_ids: List[str]) -> Dict[str, float]:
        """cpu>0.85 AND mem>0.85 (normal: cpu=0.3-0.6, mem=0.3-0.5)."""
        scores = {}
        cpu_th = self._bound("concealment", "cpu_usage", 0.85, "upper")
        mem_th = self._bound("concealment", "memory_usage", 0.85, "upper")
        for aid in agent_ids:
            info = agents.get(aid, {})
            cpu = info.get("cpu_usage", 0)
            mem = info.get("memory_usage", 0)
            if cpu > cpu_th and mem > mem_th:
                scores[aid] = min(1.0, 0.7 + (cpu - 0.85) * 2 + (mem - 0.85) * 2)
        return scores

    def _rule_premature_convergence(self, agents: dict, messages: list,
                                    interactions: list,
                                    agent_ids: List[str]) -> Dict[str, float]:
        """api<=3 AND fs_read<=5 (normal: api=4-6, fs_read=10-40)."""
        scores = {}
        api_th = self._bound("premature_convergence", "api_call_count", 3, "lower")
        read_th = self._bound("premature_convergence", "fs_read_count", 5, "lower")
        for aid in agent_ids:
            info = agents.get(aid, {})
            api = info.get("api_call_count", 0)
            fs_read = info.get("fs_read_count", 0)
            if api <= api_th and fs_read <= read_th:
                scores[aid] = 0.55
        return scores

    def _rule_supervisor_bypass(self, agents: dict, messages: list, interactions: list,
                                agent_ids: List[str],
                                topology: str = "unknown") -> Dict[str, float]:
        """2+ agent-agent bypass edges between worker agents.

        A single bypass edge occurs in normal observations (1/obs max); the
        supervisor-bypass injection adds 3 directed worker pairs (n>=4), so
        require >=2 edges to avoid false positives on normal chatter.
        """
        aid_set = set(agent_ids)
        bypass_count = 0
        for it in interactions:
            src = it.get("src", "")
            dst = it.get("dst", "")
            if src in aid_set and dst in aid_set and it.get("type") == "bypass":
                bypass_count += 1
        if bypass_count >= 2:
            return {agent_ids[0]: 0.8}
        return {}

    def _rule_group_split(self, agents: dict, messages: list, interactions: list,
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

    def _rule_flood_from_single(self, agents: dict, messages: list, interactions: list,
                                agent_ids: List[str]) -> Dict[str, float]:
        """Single source sends to 3+ distinct agent targets.

        Only agent-to-agent targets count (both src and dst are agents):
        external entities (AgentA/AgentB) and dense interaction hubs are
        normal coordination, not a peer flood.
        """
        agent_set = set(agent_ids)
        src_dsts = {}
        for it in interactions:
            src = it.get("src", "")
            dst = it.get("dst", "")
            if src in agent_set and dst in agent_set:
                src_dsts.setdefault(src, set()).add(dst)
        for m in messages:
            src = m.get("src", "")
            dst = m.get("dst", "")
            if src in agent_set and dst in agent_set:
                src_dsts.setdefault(src, set()).add(dst)
        for src, dsts in src_dsts.items():
            threshold = 3 if len(agent_ids) >= 6 else (2 if len(agent_ids) >= 3 else 99)
            if len(dsts) >= threshold:
                return {src: min(0.75, 0.45 + 0.06 * len(dsts))}
        return {}

    def _rule_message_storm(self, agents: dict, messages: list, interactions: list,
                            agent_ids: List[str]) -> Dict[str, float]:
        """Agent with high msg_received and many incoming interactions."""
        incoming = {}
        for it in interactions:
            dst = it.get("dst", "")
            if dst in agent_ids:
                incoming[dst] = incoming.get(dst, 0) + 1
        recv_th = self._bound("message_storm", "msg_received", 30, "upper")
        for aid in agent_ids:
            info = agents.get(aid, {})
            recv = info.get("msg_received", 0)
            inc = incoming.get(aid, 0)
            if recv >= recv_th and inc >= 5:
                score = min(0.80, 0.45 + 0.01 * recv)
                return {aid: score}
        return {}

    # ── Rule registry ──

    RULES: List[str] = [
        "stale_state",
        "state_conflict",
        "partial_visibility",
        "message_disorder",
        "timeout_retry",
        "ignore_input",
        "reasoning_action_mismatch",
        "wrong_assumption",
        "task_derailment",
        "concealment",
        "premature_convergence",
        "supervisor_bypass",
        "group_split",
        "flood_from_single",
        "message_storm",
    ]

    # ── Public API ──

    def __init__(self, risk_threshold: float = 0.5,
                 adaptive: bool = False,
                 adaptive_cfg: Optional[dict] = None,
                 posterior_path: Optional[str] = None):
        self._risk_threshold = risk_threshold
        self._posterior_path = posterior_path
        cfg = adaptive_cfg or {}
        self._adaptive_cfg = cfg
        self._adaptive = AdaptiveBoundaryState(
            adaptive=bool(adaptive),
            forget_alpha=cfg.get("forget_alpha", 0.02),
            burn_in=cfg.get("burn_in", 20),
            clamp_min=cfg.get("clamp_min", 0.5),
            clamp_max=cfg.get("clamp_max", 1.5),
            posterior_min=cfg.get("posterior_min", 0.6),
            initial_std_ratio=cfg.get("initial_std_ratio", 0.2),
        )
        for metric, (mean, std) in self.ADAPTIVE_SEEDS.items():
            self._adaptive.seed_metric(metric, mean)
        for rule, metric, anchor, direction in self.ADAPTIVE_BOUNDS:
            self._adaptive.register_bound(rule, metric, anchor, direction)
        if adaptive and posterior_path and os.path.isfile(posterior_path):
            try:
                with open(posterior_path, "r", encoding="utf-8") as f:
                    self._adaptive.load_state(json.load(f))
            except Exception as e:
                logger.warning("Failed to load semantic posterior %s: %s",
                               posterior_path, e)

    @property
    def adaptive(self) -> bool:
        return self._adaptive.adaptive

    def check(self, obs: dict) -> dict:
        """Run all rules against a single observation."""
        agents_data = obs.get("agents", {})
        agent_ids = list(agents_data.keys())
        messages = obs.get("messages", [])
        interactions = obs.get("interactions", [])
        topology = obs.get("_topology", "unknown")

        all_agent_scores: Dict[str, float] = {}
        types_found: Dict[str, Dict[str, float]] = {}

        for type_name in self.RULES:
            rule_fn = getattr(self, "_rule_" + type_name)
            try:
                if type_name == "supervisor_bypass":
                    per_agent = rule_fn(agents_data, messages, interactions,
                                        agent_ids, topology=topology)
                else:
                    per_agent = rule_fn(agents_data, messages, interactions, agent_ids)
            except Exception as e:
                logger.warning("Rule %s raised: %s", type_name, e)
                per_agent = {}
            scale = self._adaptive.rule_scale(type_name)
            for aid, risk in per_agent.items():
                if risk <= 0.0 or aid not in agent_ids:
                    continue
                risk *= scale
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

    def update(self, obs: dict, p_anomaly: Optional[float] = None):
        """Online Bayesian update from a (possibly labelled) observation.

        No-op unless adaptive mode is enabled. The rule check runs first so the
        firing decision uses the pre-update bounds; normal observations then
        update the per-metric baseline (absorbing drift) and any rule that
        still fired on them is recorded as a false positive. Anomalous
        observations never pollute the baseline and only feed true-positive
        feedback to the fired rules.

        ``p_anomaly`` enables weak-label gating for live data that has no
        ground-truth label: only decisive confidence counts as evidence
        (``p >= weak_label_hi`` -> TP, ``p <= weak_label_lo`` -> FP), while
        ambiguous windows skip the Beta update entirely so they cannot inflate
        the posterior. When ``p_anomaly`` is None the hard label on the obs is
        used (stored/demo mode keeps the previous behaviour).
        """
        if not self._adaptive.adaptive:
            return
        try:
            if p_anomaly is None:
                label = obs.get("label")
                atype = obs.get("_anomaly_type")
                anomalous = bool(label) or bool(
                    atype and atype not in ("", "normal", None))
            else:
                hi = float(self._adaptive_cfg.get("weak_label_hi", 0.6))
                lo = float(self._adaptive_cfg.get("weak_label_lo", 0.3))
                if p_anomaly >= hi:
                    anomalous = True
                elif p_anomaly <= lo:
                    anomalous = False
                else:
                    anomalous = None

            result = self.check(obs)
            fired = result.get("anomaly_types", [])
            agents_data = obs.get("agents", {})
            if anomalous is False:
                for metric in self.ADAPTIVE_SEEDS:
                    for aid, info in agents_data.items():
                        if metric in info:
                            self._adaptive.update_normal_metric(metric, info[metric])
            if anomalous is not None:
                for rule in fired:
                    self._adaptive.update_beta(rule, tp=anomalous, fp=not anomalous)
            self.persist()
        except Exception as e:
            logger.warning("Semantic adaptive update failed: %s", e)

    def persist(self):
        if not self._posterior_path:
            return
        try:
            d = os.path.dirname(os.path.abspath(self._posterior_path))
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            with open(self._posterior_path, "w", encoding="utf-8") as f:
                json.dump(self._adaptive.to_dict(), f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("Failed to persist semantic posterior: %s", e)

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

        for type_name in self.RULES:
            rule_fn = getattr(self, "_rule_" + type_name)
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
