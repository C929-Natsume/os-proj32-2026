#!/usr/bin/env python3
"""
Train GNN-based anomaly detector using simulated eBPF metric data.

Pipeline:
  1. Generate or load simulated dataset (normal + anomaly) as JSON files
  2. Build graphs from observations (AgentInteractionGraph)
  3. Unsupervised DOMINANT pre-training on normal data only
  4. Semi-supervised fine-tuning with a small labeled set
  5. Evaluate on test set (AUC-ROC, Precision@K)
  6. Save trained model to models/anomaly_detector.pth

Usage:
    python examples/train.py                          # fresh dataset + train
    python examples/train.py --load-dir training_data  # reuse saved dataset
    python examples/train.py --epochs 50 --lr 0.0005
"""

import argparse
import json
import os
import sys
import time
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    print("ERROR: PyTorch not installed. Install with: pip install torch")
    sys.exit(1)

from inter_agent.data.simulator import Simulator
from inter_agent.data.text_encoder import ContentFeatureExtractor, DEFAULT_CONTENT_DIM
from inter_agent.data.features import extract_node_features, extract_edge_attributes, NODE_FEATURE_DIM
from inter_agent.graph.builder import AgentInteractionGraph
from inter_agent.detection.gnn_detector import (
    DOMINANT, AnomalyClassifier, build_adjacency_matrix,
)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ============================================================
# Data loading and graph construction
# ============================================================

def observation_to_pyg(obs: dict, content_extractor=None):
    """Convert observation dict to per-node tensors.

    Returns (x, edge_index, edge_attr, node_labels) where:
      x: node features [N, 14] (no content) or [N, 22] (with content)
      edge_index: [2, E]
      edge_attr: [E, 6] — onehot type(3) + weight + data_size_norm + msg_count_norm
      node_labels: [N] — 1 for anomalous agent, 0 otherwise
    """
    agents_data = obs.get("agents", {})
    interactions = obs.get("interactions", [])
    agent_ids = sorted(agents_data.keys())
    n = len(agent_ids)
    aid_to_idx = {aid: i for i, aid in enumerate(agent_ids)}

    x_np = extract_node_features(agents_data, agent_ids, interactions)
    if content_extractor is not None:
        from inter_agent.data.text_encoder import DEFAULT_CONTENT_DIM
        content_feats = content_extractor.extract(
            agents_data, agent_ids, interactions, obs.get("messages"))
        if any(aid in content_feats for aid in agent_ids):
            dim = NODE_FEATURE_DIM + DEFAULT_CONTENT_DIM
            x_ext = np.zeros((n, dim), dtype=np.float32)
            x_ext[:, :NODE_FEATURE_DIM] = x_np
            for aid, i in aid_to_idx.items():
                if aid in content_feats:
                    cf = content_feats[aid]
                    for k in range(min(len(cf), DEFAULT_CONTENT_DIM)):
                        x_ext[i, NODE_FEATURE_DIM + k] = min(float(cf[k]), 1.0)
            x_np = x_ext
    x = torch.from_numpy(x_np).float()

    edge_attr_np = extract_edge_attributes(interactions, aid_to_idx)
    edge_list = [[aid_to_idx[it["src"]], aid_to_idx[it["dst"]]]
                 for it in interactions
                 if it["src"] in aid_to_idx and it["dst"] in aid_to_idx]
    if not edge_list:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_attr = torch.zeros((0, 6), dtype=torch.float)
    else:
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        edge_attr = torch.from_numpy(edge_attr_np).float() if edge_attr_np is not None else torch.zeros((0, 6), dtype=torch.float)

    target = obs.get("_anomaly_target", None)
    node_labels = torch.zeros(n, dtype=torch.float)
    if target is not None:
        if isinstance(target, str):
            idx = aid_to_idx.get(target)
            if idx is not None:
                node_labels[idx] = 1.0
        elif isinstance(target, list):
            for aid in target:
                idx = aid_to_idx.get(aid)
                if idx is not None:
                    node_labels[idx] = 1.0
    return x, edge_index, edge_attr, node_labels


class GraphDataset:
    """In-memory dataset of graphs with per-node labels and edge features."""

    def __init__(self, observations: list, content_extractor=None):
        self.samples = []
        self.node_labels = []
        self.graph_labels = []
        self.anomaly_types = []
        self.topologies = []
        for obs in observations:
            x, edge_index, edge_attr, node_labels = observation_to_pyg(obs, content_extractor)
            self.samples.append((x, edge_index, edge_attr))
            self.node_labels.append(node_labels)
            self.graph_labels.append(int(obs.get("label", 0)))
            self.anomaly_types.append(str(obs.get("_anomaly_type", "none")))
            self.topologies.append(obs.get("_topology", None))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx], self.node_labels[idx], self.graph_labels[idx], self.anomaly_types[idx], self.topologies[idx]


# ============================================================
# Training functions
# ============================================================

class EarlyStopping:
    def __init__(self, patience=10, min_delta=1e-4):
        self.patience = patience
        self.min_delta = min_delta
        self.best_loss = float("inf")
        self.counter = 0

    def check(self, loss):
        if loss < self.best_loss - self.min_delta:
            self.best_loss = loss
            self.counter = 0
            return False
        self.counter += 1
        return self.counter >= self.patience


def pretrain_dominant(model, dataset, epochs=20, lr=0.001):
    """Unsupervised DOMINANT pre-training on normal data."""
    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, patience=5, factor=0.5, min_lr=1e-5
    )
    early_stop = EarlyStopping(patience=10)
    n = len(dataset)

    for epoch in range(1, epochs + 1):
        perm = torch.randperm(n)
        epoch_loss = 0.0
        n_graphs = 0

        for idx in perm.tolist():
            (x, edge_index, edge_attr), _, _, _, topo = dataset[idx]
            x, edge_index = x.to(DEVICE), edge_index.to(DEVICE)
            edge_attr = edge_attr.to(DEVICE) if edge_attr.size(0) > 0 else None

            optimizer.zero_grad()
            result = model.compute_loss(x, edge_index, edge_attr, topology=topo)
            if isinstance(result, tuple) and len(result) == 5:
                loss, feat_loss, struct_loss, edge_loss, kl_loss = result
            elif isinstance(result, tuple) and len(result) == 4:
                loss, feat_loss, struct_loss, edge_loss = result
            else:
                loss, feat_loss, struct_loss = result
                edge_loss = torch.tensor(0.0)
            if torch.isnan(loss).any() or torch.isinf(loss).any():
                continue
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()
            n_graphs += 1

        avg_loss = epoch_loss / max(n_graphs, 1)
        scheduler.step(avg_loss)
        if epoch % 5 == 0 or epoch == 1:
            print(f"  Epoch {epoch:3d}/{epochs}  loss={avg_loss:.6f}  "
                  f"feat={feat_loss.item() if hasattr(feat_loss, 'item') else feat_loss:.6f}  "
                  f"struct={struct_loss.item() if hasattr(struct_loss, 'item') else struct_loss:.6f}  "
                  f"edge={edge_loss.item() if hasattr(edge_loss, 'item') else edge_loss:.6f}")

        if early_stop.check(avg_loss):
            print(f"  Early stopping at epoch {epoch}")
            break

    return True


def finetune_classifier(model, classifier, dataset, epochs=30, lr=0.001):
    """Semi-supervised fine-tuning with per-node labels."""
    model.train()
    classifier.train()
    optimizer = torch.optim.Adam(
        list(model.parameters()) + list(classifier.parameters()), lr=lr
    )
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, patience=5, factor=0.5, min_lr=1e-5
    )
    early_stop = EarlyStopping(patience=10)
    cls_criterion = nn.BCEWithLogitsLoss()
    beta = 0.05

    n = len(dataset)
    for epoch in range(1, epochs + 1):
        perm = torch.randperm(n)
        epoch_loss = 0.0
        epoch_cls_loss = 0.0
        n_graphs = 0

        for idx in perm.tolist():
            (x, edge_index, edge_attr), node_labels, _, _, topo = dataset[idx]

            optimizer.zero_grad()
            if model.variant == "variational":
                _, _, _, z, _, _ = model(x, edge_index, edge_attr)
            else:
                _, _, _, z = model(x, edge_index, edge_attr)

            result = model.compute_loss(x, edge_index, edge_attr, topology=topo)
            if isinstance(result, tuple) and len(result) == 5:
                dom_loss, feat_loss, struct_loss, edge_loss, kl_loss = result
                dom_loss = dom_loss + kl_loss
            elif isinstance(result, tuple) and len(result) == 4:
                dom_loss, feat_loss, struct_loss, edge_loss = result
            else:
                dom_loss, feat_loss, struct_loss = result
                edge_loss = torch.tensor(0.0)
            logits = classifier(z)
            cls_loss = cls_criterion(logits, node_labels)
            if torch.isnan(dom_loss).any() or torch.isinf(dom_loss).any():
                loss = beta * cls_loss
            else:
                loss = dom_loss + beta * cls_loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(
                list(model.parameters()) + list(classifier.parameters()), 1.0
            )
            optimizer.step()

            epoch_loss += loss.item()
            epoch_cls_loss += cls_loss.item()
            n_graphs += 1

        avg_loss = epoch_loss / max(n, 1)
        avg_cls = epoch_cls_loss / max(n, 1)
        scheduler.step(avg_loss)
        if epoch % 10 == 0 or epoch == 1:
            print(f"  Epoch {epoch:3d}/{epochs}  total={avg_loss:.6f}  "
                  f"dom={avg_loss:.6f}  cls={avg_cls:.6f}")

        if early_stop.check(avg_loss):
            print(f"  Early stopping at epoch {epoch}")
            break


# ============================================================
# Evaluation (per-node)
# ============================================================

def evaluate(model, classifier, dataset, threshold=0.5):
    """Evaluate on test set using per-node scores and labels."""
    model.eval()
    if classifier is not None:
        classifier.eval()

    all_scores = []
    all_labels = []

    for i in range(len(dataset)):
        (x, edge_index, edge_attr), node_labels, _, _, topo = dataset[i]
        x, edge_index = x.to(DEVICE), edge_index.to(DEVICE)
        edge_attr = edge_attr.to(DEVICE) if edge_attr.size(0) > 0 else None
        with torch.no_grad():
            anom_scores, feat_err, struct_err, edge_err, z = model.compute_anomaly_scores(x, edge_index, edge_attr, topology=topo)
            if classifier is not None:
                cls_logits = classifier(z).cpu()
                cls_probs = torch.sigmoid(cls_logits).numpy()
                combined = 0.5 * anom_scores + 0.5 * cls_probs
            else:
                combined = anom_scores
        all_scores.extend(combined.tolist())
        all_labels.extend(node_labels.tolist())

    scores_arr = np.array(all_scores)
    labels_arr = np.array(all_labels)

    if len(scores_arr) > 0:
        print(f"    graph scores: min={scores_arr.min():.6f} max={scores_arr.max():.6f} std={scores_arr.std():.6f}")

    preds = (scores_arr >= threshold).astype(int)
    tp = ((preds == 1) & (labels_arr == 1)).sum()
    fp = ((preds == 1) & (labels_arr == 0)).sum()
    tn = ((preds == 0) & (labels_arr == 0)).sum()
    fn = ((preds == 0) & (labels_arr == 1)).sum()

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    accuracy = (tp + tn) / max(len(labels_arr), 1)

    try:
        from sklearn.metrics import roc_auc_score
        if len(np.unique(labels_arr)) > 1:
            auc = roc_auc_score(labels_arr, scores_arr)
        else:
            auc = 0.5
    except Exception:
        auc = 0.5

    return {
        "auc_roc": auc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "threshold": threshold,
        "mode": "per-node",
    }


# ============================================================
# Graph-level evaluation
# ============================================================

def evaluate_graph_level(model, classifier, dataset, threshold=0.5):
    """Evaluate on test set using per-graph (max node score) level."""
    model.eval()
    if classifier is not None:
        classifier.eval()

    all_graph_scores = []
    all_graph_labels = []

    for i in range(len(dataset)):
        (x, edge_index, edge_attr), _, graph_label, _, topo = dataset[i]
        x, edge_index = x.to(DEVICE), edge_index.to(DEVICE)
        edge_attr = edge_attr.to(DEVICE) if edge_attr.size(0) > 0 else None
        with torch.no_grad():
            anom_scores, feat_err, struct_err, edge_err, z = model.compute_anomaly_scores(x, edge_index, edge_attr, topology=topo)
            if classifier is not None:
                cls_logits = classifier(z).cpu()
                cls_probs = torch.sigmoid(cls_logits).numpy()
                combined = 0.5 * anom_scores + 0.5 * cls_probs
            else:
                combined = anom_scores
        graph_score = float(np.max(combined))
        all_graph_scores.append(graph_score)
        all_graph_labels.append(graph_label)

    scores_arr = np.array(all_graph_scores)
    labels_arr = np.array(all_graph_labels)

    if len(scores_arr) > 0:
        print(f"    graph scores: min={scores_arr.min():.6f} max={scores_arr.max():.6f} std={scores_arr.std():.6f}")

    preds = (scores_arr >= threshold).astype(int)
    tp = ((preds == 1) & (labels_arr == 1)).sum()
    fp = ((preds == 1) & (labels_arr == 0)).sum()
    tn = ((preds == 0) & (labels_arr == 0)).sum()
    fn = ((preds == 0) & (labels_arr == 1)).sum()

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    accuracy = (tp + tn) / max(len(labels_arr), 1)

    try:
        from sklearn.metrics import roc_auc_score
        if len(np.unique(labels_arr)) > 1:
            auc = roc_auc_score(labels_arr, scores_arr)
        else:
            auc = 0.5
    except Exception:
        auc = 0.5

    return {
        "auc_roc": auc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "threshold": threshold,
        "mode": "per-graph",
    }


# ============================================================
# Per-type anomaly analysis + threshold optimization
# ============================================================

def evaluate_per_type(model, classifier, dataset_full, threshold=0.5):
    """Per-type AUC + recall at threshold using the FULL dataset (all labels)."""
    from sklearn.metrics import roc_auc_score

    model.eval()
    if classifier is not None:
        classifier.eval()

    # Collect max scores and labels per anomaly type
    type_scores = {}
    for i in range(len(dataset_full)):
        (x, edge_index, edge_attr), _, graph_label, anom_type, topo = dataset_full[i]
        x, edge_index = x.to(DEVICE), edge_index.to(DEVICE)
        edge_attr = edge_attr.to(DEVICE) if edge_attr.size(0) > 0 else None
        with torch.no_grad():
            anom_scores, feat_err, struct_err, edge_err, z = model.compute_anomaly_scores(x, edge_index, edge_attr, topology=topo)
            if classifier is not None:
                cls_logits = classifier(z).cpu()
                cls_probs = torch.sigmoid(cls_logits).numpy()
                combined = 0.5 * anom_scores + 0.5 * cls_probs
            else:
                combined = anom_scores
            anom_type_key = anom_type if graph_label == 1 else "__normal__"
            type_scores.setdefault(anom_type_key, []).append((
                float(combined.max()), graph_label
            ))

    print("\n  [per-type analysis]")
    normal_scores = np.array([s for s, l in type_scores.get("__normal__", [])])
    for t in sorted(type_scores.keys()):
        if t == "__normal__":
            continue
        anom = np.array([s for s, l in type_scores[t]])
        n_total = len(anom)
        n_detected = int((anom >= threshold).sum())
        recall = n_detected / max(n_total, 1)
        # AUC if normal samples exist
        if len(normal_scores) > 0:
            y_true = [0] * len(normal_scores) + [1] * n_total
            y_score = list(normal_scores) + list(anom)
            try:
                auc = roc_auc_score(y_true, y_score)
            except ValueError:
                auc = float("nan")
            print(f"    {t:<20s}: recall={recall:.2%} ({n_detected}/{n_total}), AUC={auc:.4f}")
        else:
            print(f"    {t:<20s}: recall={recall:.2%} ({n_detected}/{n_total})")

    return type_scores


def optimize_threshold(model, classifier, dataset):
    """Find best threshold on validation set using F1."""
    model.eval()
    if classifier is not None:
        classifier.eval()

    all_scores = []
    all_labels = []
    for i in range(len(dataset)):
        (x, edge_index, edge_attr), _, graph_label, _, topo = dataset[i]
        x, edge_index = x.to(DEVICE), edge_index.to(DEVICE)
        edge_attr = edge_attr.to(DEVICE) if edge_attr.size(0) > 0 else None
        with torch.no_grad():
            anom_scores, feat_err, struct_err, edge_err, z = model.compute_anomaly_scores(x, edge_index, edge_attr, topology=topo)
            if classifier is not None:
                cls_logits = classifier(z).cpu()
                cls_probs = torch.sigmoid(cls_logits).numpy()
                combined = 0.5 * anom_scores + 0.5 * cls_probs
            else:
                combined = anom_scores
        all_scores.append(float(combined.max()))
        all_labels.append(graph_label)

    best_f1 = 0
    best_thresh = 0.5
    for thresh in np.arange(0.05, 0.96, 0.05):
        preds = (np.array(all_scores) >= thresh).astype(int)
        tp = ((preds == 1) & (np.array(all_labels) == 1)).sum()
        fp = ((preds == 1) & (np.array(all_labels) == 0)).sum()
        fn = ((preds == 0) & (np.array(all_labels) == 1)).sum()
        f1 = 2 * tp / max(2 * tp + fp + fn, 1)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh

    print(f"\n  [threshold optimization]")
    print(f"    Best threshold: {best_thresh:.2f} (F1={best_f1:.4f})")
    return best_thresh, best_f1


# ============================================================
# K-fold cross validation
# ============================================================

def kfold_cv(dataset_obs, n_splits=5, args=None, content_extractor=None):
    """Run K-fold cross-validation and return metrics."""
    from sklearn.model_selection import StratifiedKFold
    import copy

    normal = [o for o in dataset_obs if o.get("label", 0) == 0]
    anomaly = [o for o in dataset_obs if o.get("label", 0) == 1]

    if n_splits < 2:
        return None

    # Use graph-level labels for stratification (0=normal, 1=anomaly)
    labels = [0] * len(normal) + [1] * len(anomaly)
    all_data = normal + anomaly

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=args.seed)
    fold_aucs = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(all_data, labels)):
        print(f"\n--- Fold {fold + 1}/{n_splits} ---")
        train_obs = [all_data[i] for i in train_idx]
        val_obs = [all_data[i] for i in val_idx]

        train_ds = GraphDataset(train_obs, content_extractor)
        val_ds = GraphDataset(val_obs, content_extractor)

        in_dim = train_ds[0][0][0].size(1)
        model = DOMINANT(
            in_dim=in_dim,
            hidden_dim=args.hidden_dim,
            latent_dim=args.latent_dim,
            feature_weight=args.feature_weight,
            struct_weight=args.struct_weight,
            encoder_type=args.encoder,
            n_layers=args.n_layers,
            variant=args.variant,
            edge_dim=6,
        ).to(DEVICE)
        classifier = AnomalyClassifier(latent_dim=args.latent_dim).to(DEVICE)

        pretrain_dominant(model, train_ds, epochs=args.epochs, lr=args.lr)
        finetune_classifier(model, classifier, train_ds,
                            epochs=args.finetune_epochs, lr=args.lr)

        node_metrics = evaluate(model, classifier, val_ds, threshold=0.5)
        graph_metrics = evaluate_graph_level(model, classifier, val_ds, threshold=0.5)
        fold_aucs.append(graph_metrics["auc_roc"])
        print(f"  Fold {fold + 1} per-node AUC: {node_metrics['auc_roc']:.4f}  per-graph AUC: {graph_metrics['auc_roc']:.4f}")

    auc_arr = np.array(fold_aucs)
    print(f"\n=== K-fold CV ({n_splits} folds) ===")
    print(f"  Per-graph AUC-ROC: {auc_arr.mean():.4f} ± {auc_arr.std():.4f}")
    return {"auc_mean": float(auc_arr.mean()), "auc_std": float(auc_arr.std()),
            "fold_aucs": fold_aucs}


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Train GNN anomaly detector")
    parser.add_argument("--load-dir", default=None, help="Load existing dataset directory")
    parser.add_argument("--output-dir", default="training_data", help="Output dataset directory")
    parser.add_argument("--num-normal", type=int, default=500, help="Number of normal samples")
    parser.add_argument("--num-anomaly", type=int, default=100, help="Number of anomaly samples")
    parser.add_argument("--num-agents", type=int, default=4, help="Number of agents")
    parser.add_argument("--epochs", type=int, default=20, help="DOMINANT pre-training epochs")
    parser.add_argument("--finetune-epochs", type=int, default=30, help="Fine-tuning epochs")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--hidden-dim", type=int, default=64, help="GNN hidden dimension")
    parser.add_argument("--latent-dim", type=int, default=64, help="Latent dimension")
    parser.add_argument("--feature-weight", type=float, default=0.65, help="Feature loss weight")
    parser.add_argument("--struct-weight", type=float, default=None, help="Structure loss weight (default: 1-feature_weight)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--encoder", choices=["gcn", "gat"], default="gcn",
                        help="Encoder type")
    parser.add_argument("--n-layers", type=int, default=1, choices=[1, 2, 3],
                        help="Number of GNN layers")
    parser.add_argument("--variant", choices=["deterministic", "variational"],
                        default="deterministic", help="Model variant")
    parser.add_argument("--content", action="store_true", default=True,
                        help="Enable content-based features (default: True)")
    parser.add_argument("--no-content", action="store_false", dest="content",
                        help="Disable content-based features")
    parser.add_argument("--cv", type=int, default=0,
                        help="K-fold cross-validation (0 = skip)")
    args = parser.parse_args()

    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    print(f"Device: {DEVICE}")

    # ---- Content feature extractor ----
    content_extractor = None
    if args.content:
        from inter_agent.data.text_encoder import ContentFeatureExtractor, DEFAULT_CONTENT_DIM
        content_extractor = ContentFeatureExtractor(content_dim=DEFAULT_CONTENT_DIM)
        print(f"Content features enabled (dim={DEFAULT_CONTENT_DIM})")
    else:
        print("Content features disabled")

    # ---- Step 1: Dataset ----
    print("\n=== Step 1: Dataset ===")
    if args.load_dir and os.path.isdir(args.load_dir):
        print(f"Loading dataset from {args.load_dir} ...")
        dataset = Simulator.load_dataset(args.load_dir)
    else:
        print(f"Generating {args.num_normal} normal + {args.num_anomaly} anomaly samples ...")
        sim = Simulator(num_agents=args.num_agents, seed=args.seed)
        meta = sim.generate_dataset(
            num_normal=args.num_normal,
            num_anomaly=args.num_anomaly,
            output_dir=args.output_dir,
        )
        print(f"  Dataset saved to {args.output_dir}/")
        print(f"  Train unlabeled: {meta['train_unlabeled']}")
        print(f"  Train labeled:   {meta['train_labeled']}")
        print(f"  Val labeled:     {meta['val_labeled']}")
        print(f"  Test labeled:    {meta['test_labeled']}")
        dataset = Simulator.load_dataset(args.output_dir)

    train_unlabeled = GraphDataset(dataset["train_unlabeled"], content_extractor)
    train_labeled = GraphDataset(dataset["train_labeled"], content_extractor)
    val_labeled = GraphDataset(dataset["val_labeled"], content_extractor)
    test_labeled = GraphDataset(dataset["test_labeled"], content_extractor)

    print(f"  Train unlabeled grapahs: {len(train_unlabeled)}")
    print(f"  Train labeled grapahs:   {len(train_labeled)}")
    print(f"  Val labeled grapahs:     {len(val_labeled)}")
    print(f"  Test labeled grapahs:    {len(test_labeled)}")

    # ---- CV mode (skip main training) ----
    if args.cv > 1:
        all_obs = (
            dataset["train_unlabeled"] + dataset["train_labeled"] +
            dataset["val_labeled"] + dataset["test_labeled"]
        )
        # Deduplicate by observation fingerprint
        seen = set()
        unique = []
        for o in all_obs:
            fp = json.dumps(o, sort_keys=True, default=str)
            if fp not in seen:
                seen.add(fp)
                unique.append(o)
        kfold_cv(unique, n_splits=args.cv, args=args, content_extractor=content_extractor)
        return

    # ---- Step 2: Build model ----
    print("\n=== Step 2: Build DOMINANT Model ===")
    in_dim = train_unlabeled[0][0][0].size(1)
    model = DOMINANT(
        in_dim=in_dim,
        hidden_dim=args.hidden_dim,
        latent_dim=args.latent_dim,
        feature_weight=args.feature_weight,
        struct_weight=args.struct_weight,
        encoder_type=args.encoder,
        n_layers=args.n_layers,
        variant=args.variant,
        edge_dim=6,
    ).to(DEVICE)
    classifier = AnomalyClassifier(latent_dim=args.latent_dim).to(DEVICE)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  DOMINANT parameters: {total_params:,}")
    print(f"  Classifier parameters: {sum(p.numel() for p in classifier.parameters()):,}")
    print(f"  Encoder: {args.encoder}, layers: {args.n_layers}, variant: {args.variant}")

    # ---- Step 3: Unsupervised pre-training ----
    print("\n=== Step 3: DOMINANT Pre-training (unsupervised) ===")
    t0 = time.time()
    pretrain_dominant(model, train_unlabeled,
                      epochs=args.epochs, lr=args.lr)
    t_pretrain = time.time() - t0
    print(f"  Done in {t_pretrain:.1f}s")

    # ---- Step 4: Evaluate pre-trained model ----
    print("\n=== Step 4: Evaluate Pre-trained Model ===")
    val_metrics = evaluate(model, None, val_labeled, threshold=0.5)
    print("  [per-node]")
    for k, v in val_metrics.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")
    test_metrics = evaluate(model, None, test_labeled, threshold=0.5)
    print("  [per-node]")
    for k, v in test_metrics.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")
    val_graph = evaluate_graph_level(model, None, val_labeled, threshold=0.5)
    print("  [per-graph]")
    for k, v in val_graph.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")
    test_graph = evaluate_graph_level(model, None, test_labeled, threshold=0.5)
    print("  [per-graph]")
    for k, v in test_graph.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")

    # ---- Step 5: Semi-supervised fine-tuning ----
    print("\n=== Step 5: Semi-supervised Fine-tuning ===")
    t0 = time.time()
    finetune_classifier(model, classifier, train_labeled,
                        epochs=args.finetune_epochs, lr=args.lr)
    t_finetune = time.time() - t0
    print(f"  Done in {t_finetune:.1f}s")

    # ---- Step 6: Evaluate fine-tuned model ----
    print("\n=== Step 6: Evaluate Fine-tuned Model ===")
    val_ft = evaluate(model, classifier, val_labeled, threshold=0.5)
    print("  [per-node]")
    for k, v in val_ft.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")
    test_ft = evaluate(model, classifier, test_labeled, threshold=0.5)
    print("  [per-node]")
    for k, v in test_ft.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")
    val_graph_ft = evaluate_graph_level(model, classifier, val_labeled, threshold=0.5)
    print("  [per-graph]")
    for k, v in val_graph_ft.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")
    test_graph_ft = evaluate_graph_level(model, classifier, test_labeled, threshold=0.5)
    print("  [per-graph]")
    for k, v in test_graph_ft.items():
        if isinstance(v, float):
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")

    # ---- Step 7: Per-type analysis + threshold optimization ----
    print("\n=== Step 7: Threshold Optimization (on val set) ===")
    best_thresh, best_f1 = optimize_threshold(model, classifier, val_labeled)
    print(f"\n=== Step 7b: Per-type Analysis (val+test, threshold={best_thresh:.2f}) ===")
    from torch.utils.data import ConcatDataset
    full_labeled = ConcatDataset([val_labeled, test_labeled])
    evaluate_per_type(model, classifier, full_labeled, threshold=best_thresh)
    if best_thresh != 0.5:
        print(f"  Re-evaluating test with optimized threshold={best_thresh:.2f}:")
        test_graph_opt = evaluate_graph_level(model, classifier, test_labeled, threshold=best_thresh)
        for k, v in test_graph_opt.items():
            if isinstance(v, float):
                print(f"    {k}: {v:.4f}")
            else:
                print(f"    {k}: {v}")

    # ---- Step 8: Save model ----
    print("\n=== Step 8: Save Model ===")
    os.makedirs("models", exist_ok=True)
    torch.save({
        "model_state_dict": model.state_dict(),
        "classifier_state_dict": classifier.state_dict(),
        "args": vars(args),
        "val_metrics_pretrain": val_metrics,
        "val_metrics_finetune": val_ft,
        "test_metrics_pretrain": test_metrics,
        "test_metrics_finetune": test_ft,
        "test_graph_pretrain": test_graph,
        "test_graph_finetune": test_graph_ft,
    }, "models/anomaly_detector.pth")
    print("  Saved to models/anomaly_detector.pth")

    print("\n=== Training Complete ===")
    print(f"  Pre-training: {t_pretrain:.1f}s, Fine-tuning: {t_finetune:.1f}s")
    print(f"  Test AUC-ROC per-node (pre-train): {test_metrics['auc_roc']:.4f}")
    print(f"  Test AUC-ROC per-node (fine-tune): {test_ft['auc_roc']:.4f}")
    print(f"  Test AUC-ROC per-graph (pre-train): {test_graph['auc_roc']:.4f}")
    print(f"  Test AUC-ROC per-graph (fine-tune): {test_graph_ft['auc_roc']:.4f}")


if __name__ == "__main__":
    main()
