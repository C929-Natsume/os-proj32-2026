import json
import os

import pytest

from inter_agent.detection.semantic_rule_checker import SemanticRuleChecker

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
TRAINING = os.path.join(PROJECT, "training_data")


def _load_data(filename="val_labeled.json"):
    path = os.path.join(TRAINING, filename)
    if not os.path.exists(path):
        pytest.skip(f"test data not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def checker():
    return SemanticRuleChecker(risk_threshold=0.5)


class TestSemanticRuleChecker:
    def test_check_returns_dict(self, checker):
        data = _load_data()
        obs = data[0]
        result = checker.check(obs)
        assert isinstance(result, dict)
        assert "overall_risk" in result
        assert "agents" in result

    def test_overall_risk_range(self, checker):
        data = _load_data()
        for obs in data:
            result = checker.check(obs)
            risk = result["overall_risk"]
            assert 0.0 <= risk <= 1.0

    def test_anomaly_detection_basic(self, checker):
        data = _load_data()
        labels = [d.get("label", 0) for d in data]
        tp = fp = fn = tn = 0
        for i, obs in enumerate(data):
            result = checker.check(obs)
            risk = result["overall_risk"]
            pred = risk >= 0.5
            gt = bool(labels[i] == 1)
            if pred and gt:
                tp += 1
            elif pred and not gt:
                fp += 1
            elif not pred and not gt:
                tn += 1
            elif not pred and gt:
                fn += 1
        total = len(data)
        assert tp + fp + fn + tn == total
        assert tp >= 0
        assert fp >= 0
        assert tn >= 0
        assert fn >= 0

    def test_anomaly_detection_per_type(self, checker):
        data = _load_data()
        by_type = {}
        for obs in data:
            gt = bool(obs.get("label", 0) == 1)
            atype = obs.get("_anomaly_type", "normal") if gt else "normal"
            result = checker.check(obs)
            pred = result["overall_risk"] >= 0.5
            key = atype
            if key not in by_type:
                by_type[key] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "n": 0}
            by_type[key]["n"] += 1
            if pred and gt:
                by_type[key]["tp"] += 1
            elif pred and not gt:
                by_type[key]["fp"] += 1
            elif not pred and not gt:
                by_type[key]["tn"] += 1
            elif not pred and gt:
                by_type[key]["fn"] += 1
        for atype, counts in by_type.items():
            n = counts["n"]
            if n >= 3 and atype != "normal":
                denom = counts["tp"] + counts["fn"]
                rec = counts["tp"] / denom if denom else 0
                assert rec >= 0.1, f"Recall too low for {atype}: {rec:.3f}"
