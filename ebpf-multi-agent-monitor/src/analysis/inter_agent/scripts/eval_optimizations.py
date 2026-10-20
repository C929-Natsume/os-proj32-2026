#!/usr/bin/env python3
"""Per-optimization evaluation harness.

Evaluates the three optimizations individually and jointly on the SAME
test_labeled.json using the full MonitorAgent pipeline, with the same metric
methodology as eval_combined_system.py (report.max_risk >= 0.3).

Configurations:
  baseline : all optimizations OFF (reproduces the current default)
  p0       : P0 Bayesian adaptive semantic thresholds
  p1       : P1 sparse GNN structure decoding
  p2       : P2 communication fingerprint bank (frozen, pre-learned)
  all      : P0 + P1 + P2 jointly

Offline warm-up from train_labeled.json (never touches the test set):
  P0: replay all labeled train windows through SemanticRuleChecker.update()
      to absorb normal baselines and per-rule Beta posteriors -> posterior JSON
  P2: learn per-channel profiles from normal (label==0) train windows only
      -> fingerprint bank JSON (no anomaly windows pollute the bank)
"""
import argparse
import copy
import json
import os
import sys
import time

import numpy as np

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, BASE)

from inter_agent.config import load_config
from inter_agent.monitor.agent import MonitorAgent
from inter_agent.detection.semantic_rule_checker import SemanticRuleChecker
from inter_agent.data.fingerprint_bank import CommunicationFingerprintBank

TRAIN_PATH = os.path.join(BASE, "training_data", "train_labeled.json")
TEST_PATH = os.path.join(BASE, "training_data", "test_labeled.json")
POSTERIOR_PATH = os.path.join(BASE, "models", "semantic_posterior.json")
BANK_PATH = os.path.join(BASE, "models", "fingerprint_bank.json")
MODEL_PATH = os.path.join(BASE, "models", "anomaly_detector.pth")

THRESH = 0.3
FP_WEIGHT = 0.35
NODE_TYPES = {"resource", "security", "worker_isolated", "reasoning_action_mismatch",
    "wrong_assumption", "task_derailment", "concealment", "premature_convergence",
    "stale_state", "partial_visibility", "timeout_retry"}
EDGE_TYPES = {"state_conflict", "message_disorder", "ignore_input", "group_split",
    "supervisor_bypass", "flood_from_single", "message_storm", "propagation"}


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _base_config():
    config = load_config()
    config["llm"] = {"enabled": False}
    config["log"] = {"output_dir": None}
    config["model"]["model_path"] = MODEL_PATH
    return config


# ── offline warm-up (train set only) ────────────────────────────────────────

def warm_p0(config, posterior_path=None):
    posterior_path = posterior_path or POSTERIOR_PATH
    semantic_cfg = config["detection"]["semantic"]
    checker = SemanticRuleChecker(
        risk_threshold=config["detection"]["semantic_rule_threshold"],
        adaptive=True,
        adaptive_cfg=semantic_cfg,
        posterior_path=posterior_path,
    )
    train = _load_json(TRAIN_PATH)
    for i, obs in enumerate(train):
        checker.update(obs)
    checker.persist()
    print(f"  [P0 warm-up] {len(train)} windows -> {posterior_path}")
    return posterior_path


def warm_p2(config):
    fp_cfg = config["detection"]["fingerprint"]
    bank = CommunicationFingerprintBank(
        enabled=True,
        forget_alpha=fp_cfg.get("forget_alpha", 0.1),
        z_threshold=fp_cfg.get("z_threshold", 3.0),
        min_samples=fp_cfg.get("min_samples", 5),
        unknown_penalty=fp_cfg.get("unknown_penalty", 1.0),
        magnitude_scale=fp_cfg.get("magnitude_scale", 2.0),
        save_path=BANK_PATH,
    )
    train = _load_json(TRAIN_PATH)
    n = 0
    for obs in train:
        if obs.get("label") == 0:
            n += bank.learn(obs.get("interactions", []))
    bank.save(BANK_PATH)
    print(f"  [P2 warm-up] {len(train)} windows, normal-only, "
          f"{len(bank._channels)} channels -> {BANK_PATH}")
    return BANK_PATH


# ── evaluation ──────────────────────────────────────────────────────────────

def run_eval(agent, raw):
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
    elapsed = time.time() - t0
    return results, elapsed


def metrics(results):
    from sklearn.metrics import roc_auc_score
    labels_a = np.array([r["label"] for r in results])
    risks_a = np.array([r["max_risk"] for r in results])
    pred = risks_a >= THRESH
    tp = int(np.sum(pred & (labels_a == 1)))
    fp = int(np.sum(pred & (labels_a == 0)))
    fn = int(np.sum(~pred & (labels_a == 1)))
    tn = int(np.sum(~pred & (labels_a == 0)))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / len(labels_a)
    try:
        auc = float(roc_auc_score(labels_a, risks_a))
    except Exception:
        auc = 0.0
    return {"prec": prec, "rec": rec, "f1": f1, "auc": auc,
            "acc": acc, "fp": fp, "fn": fn, "tp": tp, "tn": tn}


def per_type_table(results):
    bt = {}
    for r in results:
        at = r["anom_type"]
        if at == "normal":
            continue
        bti = bt.setdefault(at, {"h": 0, "tot": 0})
        bti["tot"] += 1
        if r["label"] == 1 and r["max_risk"] >= THRESH:
            bti["h"] += 1
    out = {}
    for at in sorted(bt.keys()):
        bti = bt[at]
        out[at] = bti["h"] / bti["tot"] if bti["tot"] else 0.0
    return out


def build_agent(config):
    return MonitorAgent(config=config)


def run_config(name, config):
    print(f"\n=== {name} ===")
    agent = build_agent(config)
    raw = _load_json(TEST_PATH)
    results, elapsed = run_eval(agent, raw)
    m = metrics(results)
    per = per_type_table(results)
    print(f"  Time: {elapsed:.1f}s  ({elapsed / len(raw) * 1000:.0f} ms/obs)")
    print(f"  Risk>={THRESH}  Prec={m['prec']:.4f}  Rec={m['rec']:.4f}  "
          f"F1={m['f1']:.4f}  Acc={m['acc']:.4f}  AUC={m['auc']:.4f}  "
          f"FP={m['fp']}  FN={m['fn']}  (TP={m['tp']} TN={m['tn']})")
    return {"name": name, **m, "per_type": per, "elapsed": elapsed}


def scan_p0():
    """P0 hyper-parameter sensitivity; each variant warms its own posterior."""
    print("\n" + "=" * 90)
    print("  P0 PARAMETER SENSITIVITY (adaptive semantic, per-variant warm-up)")
    print("=" * 90)
    variants = []
    raw = _load_json(TEST_PATH)
    for key, vals in (("forget_alpha", [0.01, 0.02, 0.05]),
                      ("burn_in", [10, 20, 40]),
                      ("posterior_min", [0.5, 0.6, 0.7])):
        for v in vals:
            config = _base_config()
            config["detection"]["semantic"]["adaptive"] = True
            config["detection"]["semantic"][key] = v
            tmp = os.path.join(BASE, "models",
                               "scan_p0_%s_%s.json"
                               % (key, str(v).replace(".", "_")))
            config["detection"]["semantic"]["posterior_path"] = tmp
            warm_p0(config, tmp)
            results, _ = run_eval(build_agent(config), raw)
            variants.append((key, v, metrics(results)))
    print(f"  {'param':16s}{'value':>7s}{'Prec':>8}{'Rec':>8}{'F1':>8}"
          f"{'AUC':>8}{'FP':>5}{'FN':>5}")
    print("  " + "-" * 66)
    for key, v, m in variants:
        print(f"  {key:16s}{str(v):>7s}{m['prec']:>8.4f}{m['rec']:>8.4f}"
              f"{m['f1']:>8.4f}{m['auc']:>8.4f}{m['fp']:>5}{m['fn']:>5}")
    return variants


def scan_p2():
    """P2 fingerprint weight sensitivity with the frozen pre-learned bank."""
    print("\n" + "=" * 90)
    print("  P2 WEIGHT SENSITIVITY (fingerprint frozen bank)")
    print("=" * 90)
    if not os.path.isfile(BANK_PATH):
        warm_p2(_base_config())
    raw = _load_json(TEST_PATH)
    variants = []
    for w in (0.1, 0.25, 0.35, 0.5):
        config = _base_config()
        config["detection"]["fingerprint"]["enabled"] = True
        config["detection"]["fingerprint"]["learn_online"] = False
        config["detection"]["fingerprint"]["weight"] = w
        results, _ = run_eval(build_agent(config), raw)
        variants.append((w, metrics(results)))
    print(f"  {'weight':>7s}{'Prec':>8}{'Rec':>8}{'F1':>8}{'AUC':>8}{'FP':>5}{'FN':>5}")
    print("  " + "-" * 44)
    for w, m in variants:
        print(f"  {w:>7.2f}{m['prec']:>8.4f}{m['rec']:>8.4f}{m['f1']:>8.4f}"
              f"{m['auc']:>8.4f}{m['fp']:>5}{m['fn']:>5}")
    return variants


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", choices=["baseline", "p0", "p1", "p2", "all", "both"],
                    default="all")
    ap.add_argument("--scan", action="store_true",
                    help="run P0 parameter scan and P2 weight scan instead")
    ap.add_argument("--warm", action="store_true",
                    help="force re-run offline warm-up (P0 posterior / P2 bank)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    np.random.seed(args.seed)
    import torch
    torch.manual_seed(args.seed)

    if args.scan:
        scan_p0()
        scan_p2()
        return

    if args.run in ("all", "both"):
        if not (os.path.isfile(POSTERIOR_PATH) and os.path.isfile(BANK_PATH)) or args.warm:
            cfg0 = _base_config()
            warm_p0(cfg0)
            warm_p2(cfg0)

    def make(name):
        config = _base_config()
        detect = config["detection"]
        if name in ("p0", "all"):
            detect["semantic"]["adaptive"] = True
        if name in ("p1", "all"):
            config["model"]["sparse_struct"] = True
        if name in ("p2", "all"):
            detect["fingerprint"]["enabled"] = True
            detect["fingerprint"]["learn_online"] = False
            detect["fingerprint"]["weight"] = FP_WEIGHT
        return config

    order = ["baseline", "p0", "p1", "p2", "all"]
    if args.run != "all":
        order = [args.run]
    rows = [run_config(n, make(n)) for n in order]

    print("\n" + "=" * 90)
    print("  SUMMARY  (6-module MonitorAgent, max_risk>=%.1f, test_labeled.json)" % THRESH)
    print("=" * 90)
    hdr = f"  {'Config':<9}{'Prec':>8}{'Rec':>8}{'F1':>8}{'Acc':>8}{'AUC':>8}{'FP':>5}{'FN':>5}{'ms/obs':>8}"
    print(hdr)
    print("  " + "-" * 90)
    print(f"  {'baseline':<9}{0.7788:>8.4f}{0.8212:>8.4f}{0.7903:>8.4f}{'':>8}"
          f"{0.8506:>8.4f}{'':>5}{'':>5}{'':>8}  <- historical baseline (early 6-mod)")
    for r in rows:
        print(f"  {r['name']:<9}{r['prec']:>8.4f}{r['rec']:>8.4f}{r['f1']:>8.4f}"
              f"{r['acc']:>8.4f}{r['auc']:>8.4f}{r['fp']:>5}{r['fn']:>5}"
              f"{r['elapsed'] / 359 * 1000:>8.0f}")
    print()

    print("  Per-type recall (max_risk>=%.1f):" % THRESH)
    types = sorted({t for r in rows for t in r["per_type"]})
    print(f"  {'Type':32s}" + "".join(f"{r['name']:>9s}" for r in rows))
    for t in types:
        print(f"  {t:32s}" + "".join(f"{r['per_type'].get(t, 0.0):>9.3f}" for r in rows))
    print()

    out = [{"name": r["name"], "prec": r["prec"], "rec": r["rec"], "f1": r["f1"],
            "acc": r["acc"], "auc": r["auc"], "fp": r["fp"], "fn": r["fn"],
            "elapsed": r["elapsed"], "per_type": r["per_type"]} for r in rows]
    out_path = os.path.join(BASE, "models", "eval_optimizations_result.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    csv_path = os.path.join(BASE, "models", "eval_optimizations_result.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        import csv
        w = csv.writer(f)
        w.writerow(["config", "prec", "rec", "f1", "acc", "auc", "fp", "fn",
                    "elapsed_s", "ms_per_obs"])
        for r in rows:
            w.writerow([r["name"], r["prec"], r["rec"], r["f1"], r["acc"],
                        r["auc"], r["fp"], r["fn"], r["elapsed"],
                        r["elapsed"] / 359 * 1000])
    print(f"  Saved -> {out_path}")
    print(f"  Saved -> {csv_path}")


if __name__ == "__main__":
    main()
