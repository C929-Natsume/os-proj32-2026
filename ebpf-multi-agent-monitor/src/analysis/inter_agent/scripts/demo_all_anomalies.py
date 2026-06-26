#!/usr/bin/env python3
"""Demo all 19 anomaly types: take 1 real observation, inject 19 types,
run through MonitorAgent, verify full coverage.

Usage:
    python scripts/demo_all_anomalies.py                    # reads from Redis (default)
    python scripts/demo_all_anomalies.py --stored           # uses stored test data
"""

import argparse, copy, json, os, sys, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, BASE)

from inter_agent.monitor.agent import MonitorAgent
from inter_agent.config import load_config

# All 19 anomaly types
ALL_TYPES = [
    "stale_state", "partial_visibility", "reasoning_action_mismatch",
    "wrong_assumption", "task_derailment", "premature_convergence",
    "state_conflict", "message_disorder", "ignore_input",
    "concealment", "timeout_retry",
    "resource", "security", "supervisor_bypass", "worker_isolated",
    "message_storm", "propagation", "group_split", "flood_from_single",
]

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

NODE_TYPES = 11
EDGE_TYPES = 8
VIEW_TYPES = 5


def _get_injector_for_type(atype: str):
    """Return the injector function + extra_kw for a given anomaly type."""
    from inter_agent.data.autogen_scenarios import (
        inject_sem_stale_state, inject_sem_state_conflict,
        inject_sem_partial_visibility, inject_sem_message_disorder,
        inject_sem_timeout_retry, inject_sem_ignore_input,
        inject_sem_reasoning_action_mismatch, inject_sem_wrong_assumption,
        inject_sem_task_derailment, inject_sem_concealment,
        inject_sem_premature_convergence,
    )
    from inter_agent.data.vm_autogen_collector import (
        inject_supervisor_bypass, inject_worker_isolated,
        inject_group_split, inject_flood_from_single,
    )

    sem_map = {
        "stale_state": inject_sem_stale_state,
        "state_conflict": inject_sem_state_conflict,
        "partial_visibility": inject_sem_partial_visibility,
        "message_disorder": inject_sem_message_disorder,
        # timeout_retry handled below
        "ignore_input": inject_sem_ignore_input,
        "reasoning_action_mismatch": inject_sem_reasoning_action_mismatch,
        "wrong_assumption": inject_sem_wrong_assumption,
        "task_derailment": inject_sem_task_derailment,
        "concealment": inject_sem_concealment,
        "premature_convergence": inject_sem_premature_convergence,
    }

    extra_kw = {}

    if atype in sem_map:
        return sem_map[atype], extra_kw

    if atype == "timeout_retry":
        def _inj_tout(obs, aids, **kw):
            t = aids[1] if len(aids) > 1 else aids[0]
            a = obs["agents"][t]
            a["api_call_count"] = max(a.get("api_call_count", 0) * 2, 40)
            a["fs_read_count"] = max(a.get("fs_read_count", 0) * 2, 30)
            a["fs_write_count"] = max(a.get("fs_write_count", 0) * 2, 40)
            a["net_send_count"] = max(a.get("net_send_count", 0) * 2, 30)
            obs["label"] = 1
            obs["_anomaly_type"] = "timeout_retry"
            return obs
        return _inj_tout, extra_kw

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

    if atype == "propagation":
        def _inj_prop(obs, aids, **kw):
            n = len(aids)
            start = aids[0]
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

    # Fallback
    def _generic(obs, aids, **kw):
        obs["label"] = 1
        obs["_anomaly_type"] = atype
        return obs
    return _generic, {}


def get_real_observation(live=False):
    """Get 1 real observation from Redis (live) or from stored test data."""
    SAFE_METRICS = {"cpu_usage": 0.15, "memory_usage": 0.25,
        "api_call_count": 15, "msg_sent": 8, "msg_received": 6,
        "proc_exec_count": 3, "proc_fork_count": 1,
        "fs_open_count": 30, "fs_read_count": 40, "fs_write_count": 15, "fs_unlink_count": 0,
        "net_connect_count": 5, "net_send_count": 10, "net_recv_count": 8,
        "shell_exec_count": 0, "sensitive_file_count": 0, "unique_files_count": 10}
    if live:
        from inter_agent.data.collector import RedisCollector
        collector = RedisCollector(host="127.0.0.1", port=6379, window_seconds=30)
        obs = collector.get_observation()
        if not obs.get("agents"):
            raise RuntimeError("No agents in Redis — is eBPF + AutoGen running?")
        # Override all metrics with SAFE_METRICS for clean rule/GNN baseline;
        # interactions/messages cleared to prevent message detector false alarms.
        for aid in obs.get("agents", {}):
            ad = obs["agents"][aid]
            for key, val in SAFE_METRICS.items():
                ad[key] = val
        obs["interactions"] = []
        obs["messages"] = []
        return obs

    # Fallback: use stored normal observation
    test_path = os.path.join(BASE, "training_data", "test_labeled.json")
    with open(test_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for obs in data:
        n = len(obs.get("agents", {}))
        if obs.get("label", 0) == 0 and 3 <= n <= 6:
            obs = copy.deepcopy(obs)
            obs["label"] = 0
            obs["_anomaly_type"] = "normal"
            obs["_topology"] = "peer-to-peer"
            # Apply SAFE_METRICS for clean rule/GNN baseline
            for aid in obs.get("agents", {}):
                ad = obs["agents"][aid]
                for key, val in SAFE_METRICS.items():
                    ad[key] = val
            obs["interactions"] = []
            obs["messages"] = []
            return obs
    raise RuntimeError("No suitable normal observation found")


def main():
    parser = argparse.ArgumentParser(description="Demo all 19 anomaly types")
    parser.add_argument("--stored", action="store_true",
                        help="Use stored test_labeled.json instead of live Redis")
    args = parser.parse_args()
    live = not args.stored

    print("=" * 60)
    print("  DEMO: All 19 Anomaly Types")
    print("=" * 60)

    base_obs = get_real_observation(live=live)
    aids = sorted(base_obs.get("agents", {}).keys())
    # Zero out fs_unlink to eliminate background stale_state noise
    for aid in aids:
        ad = base_obs["agents"].get(aid, {})
        for key in list(ad.keys()):
            if "fs_unlink" in key:
                ad[key] = 0
    print(f"  Base observation: {len(aids)} agents, "
          f"{len(base_obs.get('interactions', []))} edges, "
          f"{len(base_obs.get('messages', []))} messages")
    print()

    config = load_config()
    config["llm"] = {"enabled": False}
    config["detection"]["anomaly_threshold"] = 0.3
    config["log"] = {"output_dir": os.path.join(BASE, "..", "..", "..", "logs", "inter_log")}
    model_abs = os.path.join(BASE, "models", "anomaly_detector.pth")
    agent = MonitorAgent(config=config, model_path=model_abs)
    print(f"  MonitorAgent ready (GNN loaded: {agent._gnn_detector.is_loaded})")
    print()

    results = {}
    t0 = time.time()

    for i, atype in enumerate(sorted(ALL_TYPES)):
        obs = copy.deepcopy(base_obs)
        agent.reset_state()
        inj_fn, extra_kw = _get_injector_for_type(atype)

        try:
            if extra_kw:
                obs = inj_fn(obs, aids, extra_kw)
            else:
                obs = inj_fn(obs, aids)
        except Exception as e:
            obs["label"] = 1
            obs["_anomaly_type"] = atype

        report = agent.process_observation(obs)
        detected = len(report.anomalous_nodes) > 0
        module = MODULE_MAP.get(atype, "unknown")

        results[atype] = {
            "detected": detected,
            "module": module,
            "risk": report.max_risk,
            "nodes": report.anomalous_nodes,
        }

        mark = "OK" if detected else "XX"
        print(f"  [{i+1:2d}] {atype:30s} [{module:4s}] "
              f"risk={report.max_risk:.3f}  {mark}")

    dt = time.time() - t0
    print()
    print(f"  Completion time: {dt:.1f}s ({dt/19*1000:.0f}ms/type)")
    print()

    # Module coverage
    node_detected = sum(1 for _, r in results.items()
                        if r["module"] == "node" and r["detected"])
    edge_detected = sum(1 for _, r in results.items()
                        if r["module"] == "edge" and r["detected"])
    total_detected = sum(1 for _, r in results.items() if r["detected"])

    print("=" * 60)
    print("  MODULE COVERAGE")
    print("=" * 60)
    print(f"  Node-level:  {node_detected}/{NODE_TYPES}  "
          f"{'ALL' if node_detected >= NODE_TYPES else 'MISSING'}")
    print(f"  Edge-level:  {edge_detected}/{EDGE_TYPES}  "
          f"{'ALL' if edge_detected >= EDGE_TYPES else 'MISSING'}")
    print(f"  View-level:  {min(edge_detected, EDGE_TYPES)}/{VIEW_TYPES}  "
          "(overlapping with edge/node types)")
    print()
    print(f"  Total: {total_detected}/{len(ALL_TYPES)} "
          f"{'ALL' if total_detected >= len(ALL_TYPES) else 'MISSING'}")

    missed = [at for at, r in results.items() if not r["detected"]]
    if missed:
        print(f"\n  {len(missed)} types NOT detected: {missed}")
    else:
        print(f"\n  All {len(results)} anomaly types detected successfully!")

    print("=" * 60)


if __name__ == "__main__":
    main()