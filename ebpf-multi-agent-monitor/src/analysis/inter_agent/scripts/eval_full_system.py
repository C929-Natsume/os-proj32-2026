#!/usr/bin/env python3
"""Unified system evaluation: GNN + SemanticRuleChecker combined."""
import json, sys, os, time, torch
import numpy as np

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, BASE)

from inter_agent.detection.gnn_detector import DOMINANT, AnomalyClassifier, extract_features
from inter_agent.detection.semantic_rule_checker import SemanticRuleChecker

TEST_PATH = os.path.join(BASE, "training_data", "test_labeled.json")
MODEL_PATH = os.path.join(BASE, "models", "anomaly_detector.pth")
DEVICE = torch.device("cpu")
GNN_THRESH, SEM_THRESH = 0.3, 0.5

NODE_TYPES = {"resource","security","worker_isolated","reasoning_action_mismatch",
    "wrong_assumption","task_derailment","concealment","premature_convergence",
    "stale_state","partial_visibility"}
EDGE_TYPES = {"state_conflict","message_disorder","ignore_input","group_split",
    "supervisor_bypass","flood_from_single","message_storm","propagation"}
VIEW_TYPES = {"propagation","group_split","message_storm","flood_from_single",
    "premature_convergence"}

with open(TEST_PATH,"r",encoding="utf-8") as f:
    raw = json.load(f)
print(f"Test: {len(raw)} obs")

def build_graph(obs):
    agents = obs.get("agents",{}); aids = sorted(agents.keys()); n = len(aids)
    if n == 0: return None
    x_np = extract_features(agents, aids, obs.get("interactions",[]))
    x = torch.tensor(x_np, dtype=torch.float)
    a2i = {aid:i for i,aid in enumerate(aids)}
    el, ea, seen = [], [], set()
    tm = {"message":0,"api_call":1,"file_share":2,"bypass":1}
    for it in obs.get("interactions",[]):
        s,d = it.get("src",""), it.get("dst","")
        if s in a2i and d in a2i:
            si,di = a2i[s], a2i[d]
            if (si,di) not in seen:
                el.append([si,di]); seen.add((si,di))
                t = tm.get(it.get("type","message"),0)
                oh = [0.,0.,0.]; oh[t] = 1.
                ds = min(float(it.get("data_size",0))/8192.,1.)
                mc = min(float(it.get("msg_count",0))/100.,1.)
                ea.append(oh + [float(it.get("weight",0.5)), ds, mc])
    if not el:
        el = [[i,(i+1)%n] for i in range(n)]
        ea = [[1.,0.,0.,0.5,0.,0.] for _ in range(n)]
    ei = torch.tensor(el, dtype=torch.long).t().contiguous()
    eat = torch.tensor(ea, dtype=torch.float)
    lb = obs.get("label",0)
    at = obs.get("_anomaly_type","normal") if lb == 1 else "normal"
    tp = obs.get("_topology","unknown")
    return {"x":x,"edge_index":ei,"edge_attr":eat,"label":lb,"anom_type":at,"topo":tp}

graphs = [g for obs in raw if (g := build_graph(obs))]
print(f"Built {len(graphs)} graphs")

ndim = graphs[0]["x"].shape[1]
ckpt = torch.load(MODEL_PATH, map_location=DEVICE, weights_only=False)
model = DOMINANT(ndim,64,64,feature_weight=0.65,encoder_type="gcn",
                 n_layers=1,variant="deterministic",edge_dim=6)
model.to(DEVICE); model.load_state_dict(ckpt["model_state_dict"]); model.eval()
cls = AnomalyClassifier(64); cls.to(DEVICE)
cls.load_state_dict(ckpt["classifier_state_dict"]); cls.eval()
checker = SemanticRuleChecker(risk_threshold=SEM_THRESH)

results = []; t0 = time.time()
for i,g in enumerate(graphs):
    x,ei,ea = g["x"].to(DEVICE), g["edge_index"].to(DEVICE), g["edge_attr"].to(DEVICE)
    with torch.no_grad():
        scores,_,_,_,z = model.compute_anomaly_scores(x,ei,ea,g["topo"])
        cp = torch.sigmoid(cls(z)).squeeze(-1).cpu().numpy()
    gnn = float(np.max(scores*0.5 + cp*0.5)) if len(scores) > 0 else 0.
    sem = checker.check(raw[i])["overall_risk"]
    com_or = (gnn >= GNN_THRESH or sem >= SEM_THRESH)
    results.append({"label":g["label"],"anom_type":g["anom_type"],
                    "gnn":gnn,"sem":sem,"com_or":com_or})
    if (i+1) % 200 == 0: print(f"  [{i+1}/{len(graphs)}]", flush=True)
print(f"\nEval: {time.time()-t0:.1f}s\n")

# ── per-observation detection log ──
log_dir = os.path.join(BASE, "..", "..", "..", "logs", "inter_log")
os.makedirs(log_dir, exist_ok=True)
log_ts = time.strftime("%Y%m%d_%H%M%S")
log_path = os.path.join(log_dir, f"eval_full_system_{log_ts}.log")
with open(log_path, "w", encoding="utf-8") as lf:
    lf.write(f"# eval_full_system: GNN OR SemRule, GNN thresh={GNN_THRESH} Sem thresh={SEM_THRESH}\n")
    for i, r in enumerate(results):
        verdict = "anomaly" if r["com_or"] else "normal"
        lf.write(f"[{verdict:7s}] obs={i:3d} label={r['label']} "
                 f"type={r['anom_type']:25s} gnn={r['gnn']:.3f} sem={r['sem']:.3f}\n")
print(f"Detection log -> {log_path}")

from sklearn.metrics import roc_auc_score
labels = np.array([r["label"] for r in results])
gnn_s  = np.array([r["gnn"] for r in results])
sem_s  = np.array([r["sem"] for r in results])

def calc(scores, thresh, is_bin=False):
    pred = scores >= 0.5 if is_bin else scores >= thresh
    tp = np.sum(pred & (labels==1)); fp = np.sum(pred & (labels==0))
    fn = np.sum(~pred & (labels==1)); tn = np.sum(~pred & (labels==0))
    n = len(labels)
    prec = tp/(tp+fp) if (tp+fp) else 0
    rec  = tp/(tp+fn) if (tp+fn) else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0
    acc  = (tp+tn)/n
    try: auc = roc_auc_score(labels, scores)
    except: auc = 0.
    return (tp,fp,fn,tn,prec,rec,f1,acc,auc)

comb_bin = np.array([1.0 if r["com_or"] else 0.0 for r in results])
gt, gf, gn, gk, gp, gr, gf1, ga, gauc = calc(gnn_s, GNN_THRESH)
st, sf, sn, sk, sp, sr, sf1, sa, sauc = calc(sem_s, SEM_THRESH)
ct, cf, cn, ck, cp, cr, cf1, ca, cauc = calc(comb_bin, 0.5, is_bin=True)

print("=" * 80)
print("                       UNIFIED SYSTEM EVALUATION")
print("=" * 80)
print(f"  Test: {len(results)} obs ({np.sum(labels==0)} normal, {np.sum(labels==1)} anomaly)")
print(f"  GNN thresh={GNN_THRESH}  SemRule thresh={SEM_THRESH}")
print(f"  Combined = (GNN >= {GNN_THRESH}) OR (SemRule >= {SEM_THRESH})")
print()
print(f"  {'':20} {'GNN':>12} {'SemRule':>12} {'Combined':>12}")
print(f"  {'Precision':20} {gp:>12.4f} {sp:>12.4f} {cp:>12.4f}")
print(f"  {'Recall':20} {gr:>12.4f} {sr:>12.4f} {cr:>12.4f}")
print(f"  {'F1':20} {gf1:>12.4f} {sf1:>12.4f} {cf1:>12.4f}")
print(f"  {'Accuracy':20} {ga:>12.4f} {sa:>12.4f} {ca:>12.4f}")
print(f"  {'AUC':20} {gauc:>12.4f} {sauc:>12.4f} {cauc:>12.4f}")
print(f"  {'FP':20} {gf:>12d} {sf:>12d} {cf:>12d}")
print(f"  {'FN':20} {gn:>12d} {sn:>12d} {cn:>12d}")

print("\n" + "=" * 80)
print("                     PER-MODULE BREAKDOWN")
print("=" * 80)
for mn, ts in [("Node",NODE_TYPES),("Edge",EDGE_TYPES),("View",VIEW_TYPES)]:
    gh,sh,ch,tot = 0,0,0,0
    for r in results:
        if r["anom_type"] in ts:
            tot += 1
            if r["label"] == 1:
                if r["gnn"] >= GNN_THRESH: gh += 1
                if r["sem"] >= SEM_THRESH: sh += 1
                if r["com_or"]: ch += 1
    gr_mod = gh/tot if tot else 0
    sr_mod = sh/tot if tot else 0
    cr_mod = ch/tot if tot else 0
    print(f"  [{mn:5s}] {len(ts)} types, {tot} samples  "
          f"GNN={gr_mod:.3f}  SemRule={sr_mod:.3f}  Combined={cr_mod:.3f}")

print("\n" + "=" * 80)
print("                     PER-TYPE DETAILS")
print("=" * 80)
print(f"  {'Type':35s} {'Mod':6s} {'GNN_r':>6} {'Sem_r':>6} {'Comb_r':>6} {'Cnt':>4}")
print("  " + "-" * 76)

def mod(at):
    if at in NODE_TYPES: return "node"
    if at in EDGE_TYPES: return "edge"
    if at in VIEW_TYPES: return "view"
    return "normal"

bt = {}
for r in results:
    at = r["anom_type"]
    bti = bt.setdefault(at, {"gh":0,"sh":0,"ch":0,"tot":0})
    bti["tot"] += 1
    if r["label"] == 1:
        if r["gnn"] >= GNN_THRESH: bti["gh"] += 1
        if r["sem"] >= SEM_THRESH: bti["sh"] += 1
        if r["com_or"]: bti["ch"] += 1

for at in sorted(bt.keys()):
    bti = bt[at]
    g_r = bti["gh"]/bti["tot"] if bti["tot"] else 0
    s_r = bti["sh"]/bti["tot"] if bti["tot"] else 0
    c_r = bti["ch"]/bti["tot"] if bti["tot"] else 0
    print(f"  {at:35s} {mod(at):6s} {g_r:6.3f} {s_r:6.3f} {c_r:6.3f} {bti['tot']:4d}")

print("\n" + "=" * 80)
print(f"  FINAL: GNN F1={gf1:.4f} AUC={gauc:.4f}  |  "
      f"SemRule F1={sf1:.4f} AUC={sauc:.4f}  |  "
      f"Combined F1={cf1:.4f} AUC={cauc:.4f}")
print("=" * 80)