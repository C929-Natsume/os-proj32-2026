#!/usr/bin/env python3
"""Validate weak-label gating against the ground-truth posterior.

Simulates LIVE mode (no labels) over val+test. Compares the final per-rule
Beta posteriors of three adaptive checkers:
  - ref   : labelled replay  (ground-truth feedback, the ideal)
  - old   : unlabelled replay, no gating  -> every fired rule counts as FP
  - gated : unlabelled replay, p_anomaly gating (new behaviour)

The gated posterior should stay close to ref, while old inflates beta for
frequently-firing rules such as state_conflict.
"""
import copy
import json
import os
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, BASE)

from inter_agent.config import load_config
from inter_agent.detection.semantic_rule_checker import SemanticRuleChecker
from inter_agent.monitor.agent import MonitorAgent

TRAIN = os.path.join(BASE, "training_data")
DATA = []
for name in ("val_labeled.json", "test_labeled.json"):
    p = os.path.join(TRAIN, name)
    with open(p, "r", encoding="utf-8") as f:
        DATA.extend(json.load(f))
print(f"Replay obs: {len(DATA)}")


def no_label(obs):
    o = copy.deepcopy(obs)
    o.pop("label", None)
    o.pop("_anomaly_type", None)
    return o


def run_agent_for_confidence():
    """Return per-obs p_anomaly (max combined risk) via the full MonitorAgent.

    The agent's own semantic checker is forced static so it neither mutates nor
    persists any posterior; only the combined risk is extracted.
    """
    config = load_config()
    config["llm"] = {"enabled": False}
    config["log"] = {"output_dir": None}
    config["model"]["model_path"] = os.path.join(BASE, "models", "anomaly_detector.pth")
    sem_cfg = config.setdefault("detection", {}).setdefault("semantic", {})
    sem_cfg["adaptive"] = False
    sem_cfg["posterior_path"] = None

    agent = MonitorAgent(config=config)
    ps = []
    t0 = time.time()
    for i, obs in enumerate(DATA):
        try:
            report = agent.process_observation(copy.deepcopy(obs))
        except Exception as e:
            print(f"  [{i}] agent error: {e}")
            report = agent.generate_report()
        ps.append(report.max_risk)
        agent.reset_state()
        if (i + 1) % 200 == 0:
            print(f"  conf [{i + 1}/{len(DATA)}]", flush=True)
    print(f"  Time: {time.time() - t0:.1f}s")
    return ps


def replay(data, p_anomaly=None):
    checker = SemanticRuleChecker(risk_threshold=0.5, adaptive=True,
                                  adaptive_cfg={"forget_alpha": 0.1,
                                                "burn_in": 5,
                                                "posterior_min": 0.6,
                                                "weak_label_hi": 0.6,
                                                "weak_label_lo": 0.3},
                                  posterior_path=None)
    for i, obs in enumerate(data):
        kw = {"p_anomaly": p_anomaly[i]} if p_anomaly is not None else {}
        checker.update(obs, **kw)
    return checker._adaptive._betas


def main():
    ps = run_agent_for_confidence()
    print("\nBuilding reference (labelled) posterior ...")
    ref = replay(DATA)
    print("Building old (unlabelled, no gating) posterior ...")
    old = replay([no_label(o) for o in DATA])
    print("Building gated (unlabelled + confidence) posterior ...")
    gated = replay([no_label(o) for o in DATA], p_anomaly=ps)

    rules = sorted(set(list(ref) + list(old) + list(gated)))
    print(f"\n{'rule':28s} {'ref(ab)':>12s} {'old(ab)':>12s} {'gated(ab)':>12s} "
          f"{'|old-ref|':>9s} {'|gated-ref|':>11s}")
    print("-" * 92)
    tot_old = tot_gated = 0.0
    for r in rules:
        def ab(b): return (b.alpha, b.beta) if b else (1.0, 1.0)
        ra, rb = ab(ref.get(r))
        oa, ob = ab(old.get(r))
        ga, gb = ab(gated.get(r))
        d_old = abs(ob - rb)
        d_gated = abs(gb - rb)
        tot_old += d_old
        tot_gated += d_gated
        print(f"{r:28s} {ra:5.0f}/{rb:<6.0f} {oa:5.0f}/{ob:<6.0f} "
              f"{ga:5.0f}/{gb:<6.0f} {d_old:8.0f} {d_gated:10.0f}")
    print("-" * 92)
    print(f"{'SUM beta deviation':28s} {tot_old:25.0f} {tot_gated:23.0f}")
    verdict = "PASS" if tot_gated < tot_old else "CHECK"
    print(f"\nVerdict: {verdict}  (gated beta deviation "
          f"{tot_gated:.0f} vs old {tot_old:.0f})")


if __name__ == "__main__":
    main()
