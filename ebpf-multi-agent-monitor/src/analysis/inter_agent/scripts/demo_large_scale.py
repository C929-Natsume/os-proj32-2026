#!/usr/bin/env python3
"""Large-scale demo: AutoGen + eBPF + MonitorAgent on 200 rounds.

Covers all 19 anomaly types (30% injection), real-time detection + log output.

Usage:
    python scripts/demo_large_scale.py                         # VM: real Redis data (default)
    python scripts/demo_large_scale.py --stored                # host: stored data (~200 obs)
"""

import argparse, copy, json, logging, os, random, sys, time
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, BASE)

from inter_agent.monitor.agent import MonitorAgent
from inter_agent.config import load_config
from inter_agent.data.anomaly_injectors import get_injector, ALL_ANOMALY_TYPES, MODULE_MAP

logger = logging.getLogger("large_demo")
logging.basicConfig(level=logging.INFO, format="[DEMO] %(asctime)s %(message)s")


def _read_observation(data_list, idx, live=False):
    """Get 1 observation: from Redis (live) or cycled from stored data."""
    from inter_agent.data import SAFE_METRICS
    if live:
        from inter_agent.data.collector import RedisCollector
        collector = RedisCollector(host="127.0.0.1", port=6379,
                                   window_seconds=30)
        obs = collector.get_observation()
        if not obs.get("agents"):
            return None
        obs["label"] = 0
        obs["_topology"] = obs.get("_topology", "unknown")
        # Override all metrics with SAFE_METRICS for clean rule/GNN baseline.
        for aid in obs.get("agents", {}):
            ad = obs["agents"][aid]
            for key, val in SAFE_METRICS.items():
                ad[key] = val
        return obs

    # Cycled from stored data
    obs = copy.deepcopy(data_list[idx % len(data_list)])
    obs["label"] = 0
    # Stale per-agent anomalies from a prior intra-agent run contradict the
    # forced label=0 and must not drive inter-agent detections here.
    obs.pop("anomalies", None)
    # Apply SAFE_METRICS for clean rule/GNN baseline
    for aid in obs.get("agents", {}):
        ad = obs["agents"][aid]
        for key, val in SAFE_METRICS.items():
            ad[key] = val
    return obs


def main():
    parser = argparse.ArgumentParser(description="Large-scale demo")
    parser.add_argument("--stored", action="store_true",
                        help="Use stored test_labeled.json instead of live Redis")
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--inject-rate", type=float, default=0.30)
    args = parser.parse_args()
    live = not args.stored

    random.seed(42)

    # 鈹€鈹€ Load data pool 鈹€鈹€
    if live:
        data_pool = []
        logger.info("Live mode: reading from Redis each round")
    else:
        test_path = os.path.join(BASE, "training_data",
                                 "test_labeled.json")
        with open(test_path, "r", encoding="utf-8") as f:
            data_pool = json.load(f)
        logger.info("Host mode: %d observations in test set", len(data_pool))

    # 鈹€鈹€ MonitorAgent 鈹€鈹€
    config = load_config()
    config["llm"] = {"enabled": False}
    config["detection"]["anomaly_threshold"] = 0.585
    config["log"] = {"output_dir": os.path.join(BASE, "..", "..", "..", "logs", "inter_log")}
    model_abs = os.path.join(BASE, "models", "anomaly_detector.pth")
    agent = MonitorAgent(config=config, model_path=model_abs)

    print("=" * 70)
    print(f"  LARGE-SCALE DEMO: {args.rounds} rounds, "
          f"{args.inject_rate * 100:.0f}% inject")
    print(f"  Base data: {'Redis live' if live else f'{len(data_pool)} test obs'}")
    print(f"  GNN loaded: {agent._gnn_detector.is_loaded}")
    print("=" * 70)
    print()

    # 鈹€鈹€ Pre-compute injection slots 鈹€鈹€
    inject_slots = set()
    for r in range(args.rounds):
        if random.random() < args.inject_rate:
            inject_slots.add(r)

    # 鈹€鈹€ Main loop 鈹€鈹€
    stats = {
        "rounds": 0, "injected": 0, "detected": 0,
        "tp": 0, "fp": 0, "tn": 0, "fn": 0,
        "by_type_injected": Counter(),
        "by_type_detected": Counter(),
        "module_detected": Counter(),
    }

    t0 = time.time()
    type_idx = 0

    for r in range(args.rounds):
        obs = _read_observation(data_pool, r, live=live)
        if obs is None:
            logger.warning("Round %d: no data from Redis, skipping", r)
            continue

        aids = sorted(obs.get("agents", {}).keys())
        atype = "normal"

        # Inject anomaly?
        if r in inject_slots:
            atype = ALL_ANOMALY_TYPES[type_idx % len(ALL_ANOMALY_TYPES)]
            type_idx += 1
            inj_fn, extra_kw = get_injector(atype)
            try:
                if extra_kw:
                    obs = inj_fn(obs, aids, **extra_kw)
                else:
                    obs = inj_fn(obs, aids)
            except Exception as e:
                obs["label"] = 1
                obs["_anomaly_type"] = atype
            stats["injected"] += 1
            stats["by_type_injected"][atype] += 1

        # 鈹€鈹€ Detect 鈹€鈹€
        agent.reset_state()
        report = agent.process_observation(obs)
        stats["rounds"] += 1

        detected = len(report.anomalous_nodes) > 0
        injected = (r in inject_slots)

        if injected and detected:
            stats["tp"] += 1
            stats["detected"] += 1
            stats["by_type_detected"][atype] += 1
            mod = MODULE_MAP.get(atype, "unknown")
            stats["module_detected"][mod] += 1
        elif injected and not detected:
            stats["fn"] += 1
        elif not injected and detected:
            stats["fp"] += 1
        else:
            stats["tn"] += 1

        # Periodic progress
        if (r + 1) % 20 == 0:
            anom = "ALERT" if detected else "PASS"
            elapsed = time.time() - t0
            logger.info(
                "Round %4d/%-4d  %s   %s  "
                "det=%d/%d  %.1f min elapsed",
                r + 1, args.rounds, anom, atype,
                stats["detected"], stats["injected"],
                elapsed / 60,
            )

    dt = time.time() - t0

    # 鈹€鈹€ Confusion Matrix & Metrics 鈹€鈹€
    tp = stats["tp"]
    fp = stats["fp"]
    tn = stats["tn"]
    fn = stats["fn"]

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    print()
    print("=" * 70)
    print(f"  FINAL SUMMARY 鈥?Discrimination Metrics")
    print("=" * 70)
    print(f"  Rounds:    {stats['rounds']}")
    print(f"  Normal:    {stats['rounds'] - stats['injected']}")
    print(f"  Injected:  {stats['injected']}")
    print(f"  Time:      {dt:.1f}s ({dt / max(stats['rounds'], 1) * 1000:.0f}ms/round)")
    print()
    print(f"  {'Confusion Matrix':45s}")
    print(f"    TP (injected+detected): {tp:>4}")
    print(f"    FN (injected+missed):   {fn:>4}")
    print(f"    FP (normal+flagged):    {fp:>4}")
    print(f"    TN (normal+passed):     {tn:>4}")
    print()
    print(f"  {'Metrics':45s}")
    print(f"    Precision:  {precision:.4f}")
    print(f"    Recall:     {recall:.4f}")
    print(f"    F1 Score:   {f1:.4f}")
    print(f"    Accuracy:   {accuracy:.4f}")
    print()

    print(f"  {'Per-type Detection':45s}")
    print(f"  {'Type':35s} {'Mod':6s} {'TP':>4} {'FN':>4} {'Rate':>6}")
    print(f"  {'-' * 60}")

    for atype in sorted(ALL_ANOMALY_TYPES):
        inj_c = stats["by_type_injected"].get(atype, 0)
        det_c = stats["by_type_detected"].get(atype, 0)
        mod = MODULE_MAP.get(atype, "?")
        fn_c = inj_c - det_c
        rate = f"{det_c / inj_c:.0%}" if inj_c else "-"
        mark = " OK" if inj_c == 0 or det_c >= inj_c * 0.5 else " !! "
        print(f"  {atype:35s} [{mod:4s}] {det_c:>4} {fn_c:>4} {rate:>6}{mark}")

    print()
    print(f"  {'Module Contribution':45s}")
    node_det = stats["module_detected"].get("node", 0)
    edge_det = stats["module_detected"].get("edge", 0)
    print(f"  Node-level:  {node_det} types with anomalies detected")
    print(f"  Edge-level:  {edge_det} types with anomalies detected")
    print("=" * 70)
    print(f"  Log output: {os.path.join(BASE, '..', '..', '..', 'logs', 'inter_log')}/")


if __name__ == "__main__":
    main()