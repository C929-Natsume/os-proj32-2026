import json, sys, os, time
sys.path.insert(0, r"D:\一些小程序\ebpf异常检测\project3136859-387615-multi\ebpf-multi-agent-monitor\src\analysis\inter_agent")
from detection.semantic_rule_checker import SemanticRuleChecker

# Load test data
val_path = r"D:\一些小程序\ebpf异常检测\project3136859-387615-multi\ebpf-multi-agent-monitor\src\analysis\inter_agent\training_data\val_labeled.json"
with open(val_path, "r", encoding="utf-8") as f:
    data = json.load(f)

n_anom = sum(1 for d in data if d.get("label") == 1)
print(f"Dataset: {len(data)} obs ({len(data)-n_anom} normal, {n_anom} anomaly)")

checker = SemanticRuleChecker(risk_threshold=0.5)

tp = tn = fp = fn = 0
by_type = {}
t0 = time.time()

for i, obs in enumerate(data):
    label = obs.get("label", 0)
    gt = bool(label == 1)
    atype = obs.get("_anomaly_type", "normal") if gt else "normal"

    result = checker.check(obs)
    risk = result["overall_risk"]
    pred = risk >= 0.5

    if pred and gt: tp += 1
    elif pred and not gt: fp += 1
    elif not pred and not gt: tn += 1
    elif not pred and gt: fn += 1

    if atype not in by_type:
        by_type[atype] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "total": 0}
    by_type[atype]["total"] += 1
    if pred and gt: by_type[atype]["tp"] += 1
    elif pred and not gt: by_type[atype]["fp"] += 1
    elif not pred and not gt: by_type[atype]["tn"] += 1
    elif not pred and gt: by_type[atype]["fn"] += 1

    gt_str = "ANOM" if gt else "norm"
    pred_str = "ANOM" if pred else "norm"
    mk = "OK" if pred == gt else "XX"
    print(f"[{i+1:3d}/{len(data)}] {gt_str}->{pred_str} risk={risk:.3f} {mk} ({atype})", flush=True)

dt = time.time() - t0
n = len(data)
prec = tp / (tp + fp) if (tp + fp) else 0
rec = tp / (tp + fn) if (tp + fn) else 0
f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

print(f"\n{'='*60}")
print(f"SemanticRuleChecker Results (threshold=0.5):")
print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
print(f"  Precision={prec:.4f} Recall={rec:.4f} F1={f1:.4f}")
print(f"  Time: {dt*1000:.0f}ms (all {len(data)} obs) = {dt*1000/len(data):.1f}ms/obs")
print(f"  FP=0: {'YES' if fp==0 else f'NO ({fp} FPs)'}")

print(f"\nPer-type breakdown:")
for t in sorted(by_type.keys()):
    bt = by_type[t]
    p = bt["tp"] / (bt["tp"] + bt["fp"]) if (bt["tp"] + bt["fp"]) else 0
    r = bt["tp"] / (bt["tp"] + bt["fn"]) if (bt["tp"] + bt["fn"]) else 0
    print(f"  {t:30s} n={bt['total']:2d}  prec={p:.3f}  rec={r:.3f}  tp={bt['tp']} fp={bt['fp']} fn={bt['fn']}")