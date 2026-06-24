"""Batch evaluation of semantic anomaly detection on val_labeled.json.

Usage:
    python -m inter_agent.tests.eval_semantic                    # baseline only (no API needed)
    python -m inter_agent.tests.eval_semantic --api-url http://localhost:11434/v1 --model qwen2.5:7b
    python -m inter_agent.tests.eval_semantic --threshold 0.4    # adjust decision threshold
"""

import json
import sys
import os
import argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.semantic_detector import SemanticAnomalyDetector


def load_data(path="training_data_qwen_only/val_labeled.json"):
    base = os.path.join(os.path.dirname(__file__), "..", "..", "..", path)
    with open(base, encoding="utf-8") as f:
        return json.load(f)


def baseline_metrics_detector(obs: dict) -> float:
    """Simple metrics-based baseline: any shell_exec or sensitive_file -> anomaly."""
    for aid, info in obs.get("agents", {}).items():
        if info.get("shell_exec_count", 0) > 0 or info.get("sensitive_file_count", 0) > 0:
            return 1.0
        if info.get("api_call_count", 0) > 10:
            return 0.7
        if info.get("cpu_usage", 0) > 0.7:
            return 0.6
    return 0.0


def evaluate(data, detector=None, threshold=0.5):
    results = []
    true_pos = true_neg = false_pos = false_neg = 0
    total_api_calls = 0
    failed_calls = 0
    by_type = {}

    for i, obs in enumerate(data):
        label = obs.get("label", 0)
        ground_truth = bool(label == 1)
        anom_type = obs.get("_anomaly_type", "normal") if label == 1 else "normal"

        if detector is not None:
            result = detector.detect(obs)
            risk = result.get("risk", 0.0)
            status = result.get("status", "failed")
            if status == "failed":
                failed_calls += 1
            elif status == "success":
                total_api_calls += 1
        else:
            risk = baseline_metrics_detector(obs)
            status = "baseline"

        predicted = risk >= threshold

        if ground_truth and predicted:
            true_pos += 1
        elif not ground_truth and not predicted:
            true_neg += 1
        elif not ground_truth and predicted:
            false_pos += 1
        elif ground_truth and not predicted:
            false_neg += 1

        results.append({
            "idx": i,
            "label": label,
            "anom_type": anom_type,
            "risk": round(risk, 4),
            "predicted": predicted,
            "status": status,
        })

        if anom_type not in by_type:
            by_type[anom_type] = {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}
        by_type[anom_type]["total"] += 1
        if ground_truth and predicted:
            by_type[anom_type]["tp"] += 1
        elif not ground_truth and not predicted:
            by_type[anom_type]["tn"] += 1
        elif not ground_truth and predicted:
            by_type[anom_type]["fp"] += 1
        elif ground_truth and not predicted:
            by_type[anom_type]["fn"] += 1

    n = len(data)
    acc = (true_pos + true_neg) / n if n else 0
    prec = true_pos / (true_pos + false_pos) if (true_pos + false_pos) else 0
    rec = true_pos / (true_pos + false_neg) if (true_pos + false_neg) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

    return {
        "total": n,
        "true_pos": true_pos,
        "true_neg": true_neg,
        "false_pos": false_pos,
        "false_neg": false_neg,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "threshold": threshold,
        "api_calls": total_api_calls,
        "failed_calls": failed_calls,
        "by_type": by_type,
        "per_sample": results,
    }


def print_report(stats, label="Results"):
    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"{'='*50}")
    print(f"  Total samples:    {stats['total']}")
    print(f"  Threshold:        {stats['threshold']}")
    print(f"  TP / TN / FP / FN: {stats['true_pos']} / {stats['true_neg']} / {stats['false_pos']} / {stats['false_neg']}")
    print(f"  Accuracy:         {stats['accuracy']:.4f}")
    print(f"  Precision:        {stats['precision']:.4f}")
    print(f"  Recall:           {stats['recall']:.4f}")
    print(f"  F1 Score:         {stats['f1']:.4f}")
    if stats.get("api_calls"):
        print(f"  API calls:        {stats['api_calls']}")
        print(f"  Failed calls:     {stats['failed_calls']}")
    if stats.get("by_type"):
        print(f"\n  Per-type breakdown:")
        for atype, counts in sorted(stats["by_type"].items()):
            t = counts["total"]
            tp = counts["tp"]
            fp = counts["fp"]
            fn = counts["fn"]
            prec = tp / (tp + fp) if (tp + fp) else 0
            rec = tp / (tp + fn) if (tp + fn) else 0
            print(f"    {atype:35s} n={t:3d}  prec={prec:.3f}  rec={rec:.3f}  tp={tp} fp={fp} fn={fn}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Evaluate semantic anomaly detection")
    parser.add_argument("--api-url", default="https://api.siliconflow.cn/v1",
                        help="Qwen API base URL")
    parser.add_argument("--api-key", default="", help="Qwen API key")
    parser.add_argument("--model", default="Qwen/Qwen2.5-14B-Instruct", help="Model name")
    parser.add_argument("--threshold", type=float, default=0.5, help="Decision threshold")
    parser.add_argument("--data", default="training_data_qwen_only/val_labeled.json", help="Dataset path")
    parser.add_argument("--detailed", action="store_true", help="Print per-sample details")
    args = parser.parse_args()

    data = load_data(args.data)

    # Show distribution
    n_anom = sum(1 for d in data if d.get("label") == 1)
    n_norm = sum(1 for d in data if d.get("label") == 0)
    print(f"  Dataset: {len(data)} obs ({n_norm} normal, {n_anom} anomaly)")

    if args.api_url:
        api_key = args.api_key or "sk-vnvjgpkafewfpaeuhfdofxeqpybbejyrkthwohdbdsrgaeaj"
        detector = SemanticAnomalyDetector(
            api_key=api_key,
            base_url=args.api_url,
            model_name=args.model,
            window_size=3,
            risk_threshold=args.threshold,
            enabled=True,
            timeout=60,
        )
        sem = evaluate(data, detector=detector, threshold=args.threshold)
        print_report(sem, f"Semantic Detector ({args.model})")

        if args.detailed:
            print("\n=== Per-sample details ===")
            for r in sem["per_sample"]:
                expected = "ANOM" if r["label"] == 1 else "norm"
                actual = "ANOM" if r["predicted"] else "norm"
                mark = "✓" if r["label"] == 1 and r["predicted"] else \
                       "✓" if r["label"] == 0 and not r["predicted"] else "✗"
                print(f"  [{mark}] obs#{r['idx']:3d} anom={r.get('anom_type','?'):25s} "
                      f"expected={expected} actual={actual} risk={r['risk']:.3f}")
    else:
        # Baseline: metrics-only detector
        baseline = evaluate(data, detector=None, threshold=args.threshold)
        print_report(baseline, "Baseline (metrics-only)")
        print("\n  Provide --api-url to run semantic detector.")
        print("  Example: python -m inter_agent.tests.eval_semantic --api-url https://api.siliconflow.cn/v1")


if __name__ == "__main__":
    main()
