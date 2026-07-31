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
from inter_agent.data.anomaly_injectors import get_injector, ALL_ANOMALY_TYPES, MODULE_MAP

NODE_TYPES = sum(1 for m in MODULE_MAP.values() if m == "node")
EDGE_TYPES = sum(1 for m in MODULE_MAP.values() if m == "edge")
VIEW_TYPES = 5

def get_real_observation(live=False):
    """Get 1 real observation from Redis (live) or from stored test data."""
    from inter_agent.data import SAFE_METRICS
    if live:
        from inter_agent.data.collector import RedisCollector
        collector = RedisCollector(host="127.0.0.1", port=6379, window_seconds=30)
        obs = collector.get_observation()
        if not obs.get("agents"):
            raise RuntimeError("No agents in Redis 鈥?is eBPF + AutoGen running?")
        # Override all metrics with SAFE_METRICS for clean rule/GNN baseline.
        for aid in obs.get("agents", {}):
            ad = obs["agents"][aid]
            for key, val in SAFE_METRICS.items():
                ad[key] = val
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

    for i, atype in enumerate(sorted(ALL_ANOMALY_TYPES)):
        obs = copy.deepcopy(base_obs)
        agent.reset_state()
        inj_fn, extra_kw = get_injector(atype)

        try:
            if extra_kw:
                obs = inj_fn(obs, aids, **extra_kw)
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
    print(f"  View-level:  {edge_detected}/{VIEW_TYPES}  "
          "(overlapping with edge/node types)")
    print()
    print(f"  Total: {total_detected}/{len(ALL_ANOMALY_TYPES)} "
          f"{'ALL' if total_detected >= len(ALL_ANOMALY_TYPES) else 'MISSING'}")

    missed = [at for at, r in results.items() if not r["detected"]]
    if missed:
        print(f"\n  {len(missed)} types NOT detected: {missed}")
    else:
        print(f"\n  All {len(results)} anomaly types detected successfully!")

    print("=" * 60)

if __name__ == "__main__":
    main()