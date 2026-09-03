"""Shared anomaly injector registry for demo scripts.

Provides a single _get_injector_for_type() function that maps anomaly
type names to injector callables, consolidating the duplicate logic
that previously lived in both demo_all_anomalies.py and demo_large_scale.py.

Usage:
    from inter_agent.data.anomaly_injectors import get_injector
    inj_fn, extra_kw = get_injector("resource")
    obs = inj_fn(obs, agent_ids, **extra_kw)
"""

from inter_agent.data.autogen_scenarios import (
    inject_sem_stale_state, inject_sem_state_conflict,
    inject_sem_partial_visibility, inject_sem_message_disorder,
    inject_sem_ignore_input, inject_sem_reasoning_action_mismatch,
    inject_sem_wrong_assumption, inject_sem_task_derailment,
    inject_sem_concealment, inject_sem_premature_convergence,
)
from inter_agent.data.vm_autogen_collector import (
    inject_supervisor_bypass, inject_worker_isolated,
    inject_group_split, inject_flood_from_single,
)

# All 19 anomaly types (canonical list)
ALL_ANOMALY_TYPES = [
    "stale_state", "partial_visibility", "reasoning_action_mismatch",
    "wrong_assumption", "task_derailment", "premature_convergence",
    "state_conflict", "message_disorder", "ignore_input",
    "concealment", "timeout_retry",
    "resource", "security", "supervisor_bypass", "worker_isolated",
    "message_storm", "propagation", "group_split", "flood_from_single",
]

# Module classification used by demo reporting
MODULE_MAP = {
    "resource": "node", "security": "node",
    "worker_isolated": "node", "reasoning_action_mismatch": "node",
    "wrong_assumption": "node", "task_derailment": "node",
    "concealment": "node", "premature_convergence": "node",
    "stale_state": "node", "partial_visibility": "node",
    "timeout_retry": "node",
    "state_conflict": "edge", "message_disorder": "edge",
    "ignore_input": "edge", "group_split": "edge",
    "supervisor_bypass": "edge", "flood_from_single": "edge",
    "message_storm": "edge", "propagation": "edge",
}


def get_injector(atype):
    """Return (injector_fn, extra_kwargs) for a given anomaly type name."""
    sem_map = {
        "stale_state": inject_sem_stale_state,
        "state_conflict": inject_sem_state_conflict,
        "partial_visibility": inject_sem_partial_visibility,
        "message_disorder": inject_sem_message_disorder,
        "ignore_input": inject_sem_ignore_input,
        "reasoning_action_mismatch": inject_sem_reasoning_action_mismatch,
        "wrong_assumption": inject_sem_wrong_assumption,
        "task_derailment": inject_sem_task_derailment,
        "concealment": inject_sem_concealment,
        "premature_convergence": inject_sem_premature_convergence,
    }

    extra_kw = {}

    # Semantic injectors (from autogen_scenarios)
    if atype in sem_map:
        return sem_map[atype], extra_kw

    # timeout_retry — custom inline (preserves original demo logic)
    if atype == "timeout_retry":
        def _inj_timeout_retry(obs, aids, **kw):
            t = aids[1] if len(aids) > 1 else aids[0]
            a = obs["agents"][t]
            a["api_call_count"] = max(a.get("api_call_count", 0) * 2, 40)
            a["fs_read_count"] = max(a.get("fs_read_count", 0) * 2, 30)
            a["fs_write_count"] = max(a.get("fs_write_count", 0) * 2, 40)
            a["net_send_count"] = max(a.get("net_send_count", 0) * 2, 30)
            obs["label"] = 1
            obs["_anomaly_type"] = "timeout_retry"
            return obs
        return _inj_timeout_retry, extra_kw

    # Metric injectors
    if atype == "resource":
        def _inj_resource(obs, aids, **kw):
            t = aids[1] if len(aids) > 1 else aids[0]
            obs["agents"][t]["cpu_usage"] = 0.95
            obs["agents"][t]["memory_usage"] = 0.92
            obs["label"] = 1
            obs["_anomaly_type"] = "resource"
            return obs
        return _inj_resource, {}

    if atype == "security":
        def _inj_security(obs, aids, **kw):
            t = aids[1] if len(aids) > 1 else aids[0]
            obs["agents"][t]["shell_exec_count"] = 3
            obs["agents"][t]["sensitive_file_count"] = 4
            obs["label"] = 1
            obs["_anomaly_type"] = "security"
            return obs
        return _inj_security, {}

    # VM-level injectors (from vm_autogen_collector)
    if atype == "supervisor_bypass":
        return inject_supervisor_bypass, {"supervisor": "agent_0",
            "workers": ["agent_1", "agent_2", "agent_3"]}

    if atype == "worker_isolated":
        return inject_worker_isolated, {"supervisor": "agent_0",
            "workers": ["agent_1", "agent_2", "agent_3"]}

    if atype == "group_split":
        return inject_group_split, {}

    if atype == "flood_from_single":
        return inject_flood_from_single, {}

    # message_storm
    if atype == "message_storm":
        def _inj_msg_storm(obs, aids, **kw):
            t = aids[1] if len(aids) > 1 else aids[0]
            for src in aids:
                if src == t:
                    continue
                for _ in range(10):
                    obs.setdefault("interactions", []).append(
                        {"src": src, "dst": t, "type": "message",
                         "weight": 0.9, "data_size": 512, "msg_count": 1,
                         "timestamp_ns": obs.get("timestamp", 0)})
            obs["agents"][t]["msg_received"] = obs["agents"][t].get("msg_received", 0) + 90
            obs["label"] = 1
            obs["_anomaly_type"] = "message_storm"
            return obs
        return _inj_msg_storm, {}

    # propagation
    if atype == "propagation":
        def _inj_prop(obs, aids, **kw):
            n = len(aids)
            for i in range(1, n):
                obs.setdefault("interactions", []).append(
                    {"src": aids[i - 1], "dst": aids[i], "type": "api_call",
                     "weight": 0.95, "data_size": 1024, "msg_count": 1,
                     "timestamp_ns": obs.get("timestamp", 0)})
                obs["agents"][aids[i]]["cpu_usage"] = min(1.0, 0.75 + 0.05 * i)
                obs["agents"][aids[i]]["api_call_count"] = (
                    obs["agents"][aids[i]].get("api_call_count", 0) + 30 * i)
            obs["label"] = 1
            obs["_anomaly_type"] = "propagation"
            return obs
        return _inj_prop, {}

    # Fallback generic injector
    def _generic(obs, aids, **kw):
        obs["label"] = 1
        obs["_anomaly_type"] = atype
        return obs
    return _generic, {}
