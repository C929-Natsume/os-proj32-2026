import json
import os

import pytest

from inter_agent.detection.adaptive_bounds import AdaptiveBoundaryState
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


class TestAdaptiveBoundaryState:
    def test_static_mode_returns_anchor(self):
        st = AdaptiveBoundaryState(adaptive=False)
        st.seed_metric("cpu_usage", 0.15)
        st.register_bound("concealment", "cpu_usage", 0.85, "upper")
        assert st.bound("concealment", "cpu_usage", 0.85, "upper") == 0.85
        assert st.rule_scale("concealment") == 1.0

    def test_bound_tracks_baseline_after_burn_in(self):
        st = AdaptiveBoundaryState(adaptive=True, burn_in=10, clamp_min=0.5,
                                   clamp_max=1.5, forget_alpha=0.2,
                                   initial_std_ratio=0.2)
        st.seed_metric("cpu_usage", 0.15)
        st.register_bound("concealment", "cpu_usage", 0.85, "upper")
        for _ in range(10):
            st.update_normal_metric("cpu_usage", 0.15)
        before = st.bound("concealment", "cpu_usage", 0.85, "upper")
        # drift baseline up to 0.6 -> boundary must rise (fewer FPs)
        for _ in range(60):
            st.update_normal_metric("cpu_usage", 0.6)
        after = st.bound("concealment", "cpu_usage", 0.85, "upper")
        assert after > before

    def test_beta_scale_dampens_after_false_positives(self):
        st = AdaptiveBoundaryState(adaptive=True, burn_in=5, posterior_min=0.6)
        for _ in range(5):
            st.update_beta("concealment", tp=False, fp=True)
        assert 0.6 <= st.rule_scale("concealment") < 1.0

    def test_beta_scale_stays_one_for_true_positives(self):
        st = AdaptiveBoundaryState(adaptive=True, burn_in=5)
        for _ in range(20):
            st.update_beta("concealment", tp=True, fp=False)
        # posterior mean (1+20)/(2+20) ~ 0.95: dampens only slightly
        assert st.rule_scale("concealment") > 0.9

    def test_state_roundtrip(self):
        st = AdaptiveBoundaryState(adaptive=True)
        st.seed_metric("cpu_usage", 0.15)
        st.register_bound("concealment", "cpu_usage", 0.85, "upper")
        st.update_normal_metric("cpu_usage", 0.2)
        st.update_beta("concealment", tp=False, fp=True)
        st2 = AdaptiveBoundaryState(adaptive=True)
        st2.load_state(st.to_dict())
        assert st2.to_dict() == st.to_dict()


class TestAdaptiveChecker:
    def test_static_checker_unchanged(self):
        """adaptive=False must match the original hardcoded behaviour."""
        checker = SemanticRuleChecker(risk_threshold=0.5)
        data = _load_data()
        for obs in data:
            r = checker.check(obs)
            assert 0.0 <= r["overall_risk"] <= 1.0

    def test_adaptive_update_is_noop_when_disabled(self):
        checker = SemanticRuleChecker(risk_threshold=0.5)
        before = checker._adaptive.to_dict()
        obs = _load_data()[0]
        checker.update(obs)
        assert checker._adaptive.to_dict() == before

    def test_update_uses_obs_label(self, tmp_path):
        cfg = {"forget_alpha": 0.5, "burn_in": 2, "posterior_min": 0.6}
        path = str(tmp_path / "post.json")
        checker = SemanticRuleChecker(risk_threshold=0.5, adaptive=True,
                                      adaptive_cfg=cfg, posterior_path=path)
        # force concealment to fire on a labelled normal obs => FP for concealment
        obs = _load_data()[0]
        for aid, info in obs.get("agents", {}).items():
            info["cpu_usage"] = 0.95
            info["memory_usage"] = 0.95
        obs["label"] = 0
        obs["_anomaly_type"] = "normal"
        checker.update(obs)
        # concealment should be recorded as FP
        beta = checker._adaptive._betas.get("concealment")
        assert beta is not None and beta.beta >= 2.0
        assert os.path.exists(path)

    def test_baseline_drift_reduces_fp(self):
        """In adaptive mode, a shifted normal baseline must not keep firing
        concealment on the new (higher) normal values."""
        static = SemanticRuleChecker(risk_threshold=0.5)
        adaptive = SemanticRuleChecker(
            risk_threshold=0.5, adaptive=True,
            adaptive_cfg={"forget_alpha": 0.2, "burn_in": 5,
                          "clamp_min": 0.5, "clamp_max": 1.5})
        obs = _load_data()[0]
        for aid, info in obs.get("agents", {}).items():
            info["cpu_usage"] = 0.7
            info["memory_usage"] = 0.7
        obs["label"] = 0
        obs["_anomaly_type"] = "normal"
        # adaptive checker: feed the new baseline as "normal" many times
        for _ in range(60):
            adaptive.update(obs)
        sr = static.check(obs)["overall_risk"]
        ar = adaptive.check(obs)["overall_risk"]
        # new normal baseline (0.7/0.7) must no longer count as concealment
        assert sr >= 0.7
        assert ar < sr


def _force_concealment(obs):
    """Force the concealment rule to fire on every agent of an obs."""
    for aid, info in obs.get("agents", {}).items():
        info["cpu_usage"] = 0.95
        info["memory_usage"] = 0.95
    return obs


class TestWeakLabelGating:
    """Weak-label gating: live obs with no ground truth must only feed the
    Beta posterior when confidence is decisive (>=hi TP, <=lo FP)."""

    def _make_checker(self, tmp_path):
        cfg = {"forget_alpha": 0.5, "burn_in": 2, "posterior_min": 0.6,
               "weak_label_hi": 0.7, "weak_label_lo": 0.3}
        path = str(tmp_path / "post.json")
        return SemanticRuleChecker(risk_threshold=0.5, adaptive=True,
                                   adaptive_cfg=cfg, posterior_path=path)

    def test_ambiguous_confidence_does_not_update_beta(self, tmp_path):
        checker = self._make_checker(tmp_path)
        obs = _force_concealment(_load_data()[0])
        obs.pop("label", None)
        obs.pop("_anomaly_type", None)
        checker.update(obs, p_anomaly=0.5)
        beta = checker._adaptive._betas.get("concealment")
        # prior only: alpha=beta=1, i.e. no evidence fed
        assert beta is None or beta.evidence == 0.0

    def test_ambiguous_does_not_absorb_baseline(self, tmp_path):
        checker = self._make_checker(tmp_path)
        obs = _load_data()[0]
        for aid, info in obs.get("agents", {}).items():
            info["cpu_usage"] = 0.95
            info["memory_usage"] = 0.95
        checker.update(obs, p_anomaly=0.5)
        stats = checker._adaptive._metrics["cpu_usage"]
        # EWMA baseline must stay at the seed (0.15), untouched by ambiguity
        assert abs(stats.mean - 0.15) < 1e-6

    def test_high_confidence_hit_records_tp(self, tmp_path):
        checker = self._make_checker(tmp_path)
        obs = _force_concealment(_load_data()[0])
        obs.pop("label", None)
        obs.pop("_anomaly_type", None)
        checker.update(obs, p_anomaly=0.9)
        beta = checker._adaptive._betas["concealment"]
        assert beta.alpha >= 2.0 and beta.beta == 1.0

    def test_high_confidence_miss_records_fp(self, tmp_path):
        checker = self._make_checker(tmp_path)
        obs = _force_concealment(_load_data()[0])
        obs.pop("label", None)
        obs.pop("_anomaly_type", None)
        checker.update(obs, p_anomaly=0.1)
        beta = checker._adaptive._betas["concealment"]
        assert beta.beta >= 2.0 and beta.alpha == 1.0

    def test_falls_back_to_label_without_confidence(self, tmp_path):
        checker = self._make_checker(tmp_path)
        obs = _force_concealment(_load_data()[0])
        obs["label"] = 1
        obs["_anomaly_type"] = "concealment"
        checker.update(obs)
        beta = checker._adaptive._betas["concealment"]
        assert beta.alpha >= 2.0 and beta.beta == 1.0
