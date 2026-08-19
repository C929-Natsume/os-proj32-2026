import json
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from sklearn.metrics import (
        confusion_matrix, precision_recall_fscore_support,
        roc_auc_score, f1_score, accuracy_score, precision_score, recall_score,
    )
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


@dataclass
class PerClassMetrics:
    anomaly_type: str
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    support: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

@dataclass
class AccuracyMetrics:
    overall_accuracy: float = 0.0
    macro_precision: float = 0.0
    macro_recall: float = 0.0
    macro_f1: float = 0.0
    weighted_f1: float = 0.0
    auc_roc: float = 0.0
    per_class: List[PerClassMetrics] = field(default_factory=list)
    confusion_matrix: List[List[int]] = field(default_factory=list)
    class_names: List[str] = field(default_factory=list)
    total_samples: int = 0


ANOMALY_TYPES = [
    "normal",
    "cpu_anomaly",
    "memory_anomaly",
    "shell_exec",
    "sensitive_file",
    "network_anomaly",
    "propagation",
    "combined",
]


def evaluate_detectors(
    agent_factory,
    labeled_observations: List[Dict],
    anomaly_types: Optional[List[str]] = None,
) -> AccuracyMetrics:
    """Run all labeled observations through MonitorAgent pipeline and evaluate."""
    if not _SKLEARN_AVAILABLE:
        return AccuracyMetrics(total_samples=len(labeled_observations))

    if anomaly_types is None:
        anomaly_types = ANOMALY_TYPES

    y_true: List[str] = []
    y_pred: List[str] = []
    y_scores: List[float] = []
    per_class_stats: Dict[str, Dict] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "support": 0}
    )

    agent = agent_factory()

    for obs in labeled_observations:
        true_label = obs.get("label", obs.get("_anomaly_target", "normal"))
        if isinstance(true_label, list):
            true_label = true_label[0] if true_label else "normal"
        if true_label == 0 or true_label is None or true_label == "":
            true_label = "normal"
        if isinstance(true_label, int):
            true_label = "normal" if true_label == 0 else _get_anomaly_type(obs)

        try:
            report = agent.process_observation(obs)
            risk = report.max_risk
            pred_label = _risk_to_label(report) if risk > 0.3 else "normal"
        except Exception:
            risk = 0.0
            pred_label = "normal"

        y_true.append(true_label)
        y_pred.append(pred_label)
        y_scores.append(risk)

        per_class_stats[true_label]["support"] += 1

    all_types = sorted(set(y_true) | set(y_pred))
    cm = confusion_matrix(y_true, y_pred, labels=all_types)

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=all_types, average=None, zero_division=0
    )

    per_class = []
    for i, cls_name in enumerate(all_types):
        pc = PerClassMetrics(
            anomaly_type=cls_name,
            precision=float(precision[i]),
            recall=float(recall[i]),
            f1=float(f1[i]),
            support=int(support[i]),
            tp=int(cm[i, i]),
            fp=int(sum(cm[j, i] for j in range(len(all_types)) if j != i)),
            fn=int(sum(cm[i, j] for j in range(len(all_types)) if j != i)),
            tn=int(
                sum(cm[j, k] for j in range(len(all_types)) if j != i
                    for k in range(len(all_types)) if k != i)
            ),
        )
        per_class.append(pc)

    auc = 0.0
    if len(set(y_true)) == 2:
        y_true_bin = [1 if t != "normal" else 0 for t in y_true]
        try:
            auc = roc_auc_score(y_true_bin, y_scores)
        except Exception:
            pass

    return AccuracyMetrics(
        overall_accuracy=float(accuracy_score(y_true, y_pred)),
        macro_precision=float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        macro_recall=float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        macro_f1=float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        weighted_f1=float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        auc_roc=auc,
        per_class=per_class,
        confusion_matrix=cm.tolist(),
        class_names=all_types,
        total_samples=len(y_true),
    )


def _get_anomaly_type(obs: Dict) -> str:
    at = obs.get("_anomaly_type", "")
    if at:
        return at.lower()
    anomalies = obs.get("anomalies", [])
    if anomalies:
        types = set()
        for a in anomalies:
            t = a.get("rule", a.get("anomaly_type", ""))
            if t:
                types.add(t.lower())
        if types:
            return "_".join(sorted(types))
    return "unknown"


def _risk_to_label(report) -> str:
    risks = {
        "cpu": report.rule_risks.get("cpu", 0),
        "memory": report.rule_risks.get("memory", 0),
        "shell": report.rule_risks.get("shell_exec", 0),
        "file": report.rule_risks.get("sensitive_file", 0),
        "propagation": report.propagation_results.get("propagation", {}).get("risk", 0) if isinstance(report.propagation_results, dict) else 0,
    }
    if not risks:
        return "normal"
    top_type = max(risks, key=risks.get)
    if risks[top_type] < 0.3:
        return "normal"
    type_map = {
        "cpu": "cpu_anomaly",
        "memory": "memory_anomaly",
        "shell": "shell_exec",
        "file": "sensitive_file",
        "propagation": "propagation",
    }
    return type_map.get(top_type, top_type)
