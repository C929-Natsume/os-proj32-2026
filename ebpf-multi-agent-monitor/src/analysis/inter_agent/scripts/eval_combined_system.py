#!/usr/bin/env python3
"""Full combined system evaluation using all 6 detection modules.

Loads test_labeled.json, runs MonitorAgent (RuleBasedDetector, GNN,
TemporalDetector, MessageDetector, PropagationAnalyzer, SemanticRuleChecker)
on each observation independently, reports overall and per-type metrics.
"""
import json, sys, os, time, copy
import numpy as np

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))

from inter_agent.config import load_config
from inter_agent.monitor.agent import MonitorAgent

TEST_PATH = os.path.join(BASE, "training_data", "test_labeled.json")
NODE_TYPES = {"resource","security","worker_isolated","reasoning_action_mismatch",
    "wrong_assumption","task_derailment","concealment","premature_convergence",
    "stale_state","partial_visibility","timeout_retry"}
EDGE_TYPES = {"state_conflict","message_disorder","ignore_input","group_split",
    "supervisor_bypass","flood_from_single","message_storm","propagation"}
VIEW_TYPES = {"propagation","group_split","message_storm","flood_from_single",
    "premature_convergence"}

with open(TEST_PATH,"r",encoding="utf-8") as f:
    raw = json.load(f)
print(f"Test: {len(raw)} obs")

config = load_config()
config["llm"] = {"enabled": False}
config["log"] = {"output_dir": None}
config["model"]["model_path"] = os.path.join(BASE, "models", "anomaly_detector.pth")

THRESH = 0.3

def run_eval(agent, label):
    results = []
    t0 = time.time()
    for i, obs in enumerate(raw):
        obs_copy = copy.deepcopy(obs)
        try:
            report = agent.process_observation(obs_copy)
        except Exception as e:
            print(f"  [{i}] Error: {e}")
            report = agent.generate_report()
        agent.reset_state()
        lb = obs.get("label", 0)
        at = obs.get("_anomaly_type", "normal") if lb == 1 else "normal"
        results.append({"label": lb, "anom_type": at, "max_risk": report.max_risk})
        if (i+1) % 200 == 0:
            print(f"  [{i+1}/{len(raw)}]", flush=True)
    print(f"  Time: {time.time()-t0:.1f}s")

    from sklearn.metrics import roc_auc_score
    labels_a = np.array([r["label"] for r in results])
    risks_a = np.array([r["max_risk"] for r in results])

    pred = risks_a >= THRESH
    tp = np.sum(pred & (labels_a==1)); fp = np.sum(pred & (labels_a==0))
    fn = np.sum(~pred & (labels_a==1)); tn = np.sum(~pred & (labels_a==0))
    n = len(labels_a)
    prec = tp/(tp+fp) if (tp+fp) else 0
    rec  = tp/(tp+fn) if (tp+fn) else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0
    acc  = (tp+tn)/n
    try: auc = roc_auc_score(labels_a, risks_a)
    except: auc = 0.

    print(f"  Risk>={THRESH}  Prec={prec:.4f}  Rec={rec:.4f}  F1={f1:.4f}  AUC={auc:.4f}  FP={fp}  FN={fn}")
    print(f"\n  {'Type':35s} {'Mod':6s} {'Risk>={}'.format(THRESH):>7} {'Cnt':>4}")
    print("  " + "-" * 66)
    bt = {}
    for r in results:
        at = r["anom_type"]
        if at == "normal": continue
        bti = bt.setdefault(at, {"h":0, "tot":0})
        bti["tot"] += 1
        if r["label"] == 1 and r["max_risk"] >= THRESH:
            bti["h"] += 1
    for at in sorted(bt.keys()):
        bti = bt[at]
        hr = bti["h"]/bti["tot"] if bti["tot"] else 0
        m = "node" if at in NODE_TYPES else ("edge" if at in EDGE_TYPES else "view")
        print(f"  {at:35s} {m:6s} {hr:7.3f} {bti['tot']:4d}")
    print()
    return f1, auc

print("=" * 80)
print("  6-MODULE COMBINED SYSTEM: with-GNN vs without-GNN")
print("=" * 80)

print("\n--- GNN loaded: True ---")
agent = MonitorAgent(config=config)
f1_gnn, auc_gnn = run_eval(agent, "with-GNN")

print("--- GNN loaded: False ---")
config2 = load_config()
config2["llm"] = {"enabled": False}
config2["log"] = {"output_dir": None}
config2["model"]["model_path"] = None  # Prevent GNN loading
agent2 = MonitorAgent(config=config2)
f1_no_gnn, auc_no_gnn = run_eval(agent2, "without-GNN")

print("=" * 80)
print("  SUMMARY")
print("=" * 80)
print(f"  GNN loaded:     F1={f1_gnn:.4f}   AUC={auc_gnn:.4f}")
print(f"  GNN not loaded: F1={f1_no_gnn:.4f}  AUC={auc_no_gnn:.4f}")
print()
print("  GNN+SemRule baseline from eval_full_system.py:")
print(f"  Combined F1=0.7889 AUC=0.7983  Recall=0.8447 Precision=0.7400")
print(f"  (OR fusion, 2 modules only)")
print("=" * 80)
