"""Online Bayesian boundary adaptation for SemanticRuleChecker.

Two lightweight, CPU-only mechanisms (both gated by ``adaptive`` so the
default behaviour is byte-identical to the static checker):

1. Metric-level drift adaptation
   Each metric keeps an exponentially-weighted mean / variance of the *normal*
   baseline.  A rule's hardcoded boundary anchor is replaced by
       upper:  B = mean + k*std
       lower:  B = mean - k*std
   where ``k`` is derived at init so that B == anchor, then B tracks the
   drifting normal baseline (clamped to [clamp_min, clamp_max]*anchor).
   This is the "adaptive trigger boundary" part.

2. Rule-level Beta-Bernoulli posterior
   Each rule keeps a Beta(alpha, beta) posterior over P(rule fires | anomaly).
   Feedback (TP when the rule fired on a confirmed anomaly, FP when it fired
   on a confirmed normal observation) increments alpha / beta.  After a
   burn-in the rule's risk scores are scaled by the posterior mean, damping
   over-firing rules to improve precision.  This is the Bayesian part.

State is JSON-serialisable so it can be persisted between restarts.
"""

import math
from typing import Dict


class MetricStats:
    """EWMA mean + variance over normal observations of one metric."""

    def __init__(self, init_mean: float, init_std: float, alpha: float = 0.02):
        self.mean = float(init_mean)
        self._var = max(float(init_std) ** 2, 1e-9)
        self._alpha = float(alpha)
        self.n = 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self._var)

    def update(self, value: float):
        self.n += 1.0
        a = self._alpha
        old_mean = self.mean
        self.mean += a * (value - self.mean)
        self._var = (1.0 - a) * (self._var + a * (value - old_mean) ** 2)
        if self._var < 1e-9:
            self._var = 1e-9

    def to_dict(self) -> dict:
        return {"mean": self.mean, "var": self._var, "n": self.n}

    @classmethod
    def from_dict(cls, d: dict, alpha: float = 0.02) -> "MetricStats":
        var = max(float(d.get("var", 1e-9)), 1e-9)
        ms = cls(float(d.get("mean", 0.0)), math.sqrt(var), alpha)
        ms._var = var
        ms.n = float(d.get("n", 0.0))
        return ms


class BetaPosterior:
    """Beta-Bernoulli posterior over P(rule fires on a true anomaly)."""

    def __init__(self, alpha: float = 1.0, beta: float = 1.0):
        self.alpha = float(alpha)
        self.beta = float(beta)

    def update(self, tp: bool = False, fp: bool = False):
        if tp:
            self.alpha += 1.0
        if fp:
            self.beta += 1.0

    @property
    def mean(self) -> float:
        denom = self.alpha + self.beta
        return self.alpha / denom if denom > 0 else 0.5

    @property
    def evidence(self) -> float:
        # number of actual updates (excludes the pseudo-count prior)
        return max(self.alpha + self.beta - 2.0, 0.0)

    def to_dict(self) -> dict:
        return {"alpha": self.alpha, "beta": self.beta}

    @classmethod
    def from_dict(cls, d: dict) -> "BetaPosterior":
        return cls(d.get("alpha", 1.0), d.get("beta", 1.0))


class AdaptiveBoundaryState:
    """Owns metric stats + per-rule Beta posteriors for the checker."""

    def __init__(self,
                 adaptive: bool = False,
                 forget_alpha: float = 0.02,
                 burn_in: int = 20,
                 clamp_min: float = 0.5,
                 clamp_max: float = 1.5,
                 posterior_min: float = 0.6,
                 initial_std_ratio: float = 0.2):
        self.adaptive = bool(adaptive)
        self._forget_alpha = float(forget_alpha)
        self.burn_in = float(burn_in)
        self.clamp_min = float(clamp_min)
        self.clamp_max = float(clamp_max)
        self.posterior_min = float(posterior_min)
        self.initial_std_ratio = float(initial_std_ratio)
        self._metrics: Dict[str, MetricStats] = {}
        self._betas: Dict[str, BetaPosterior] = {}
        # (rule, metric, anchor, direction) -> k  (direction in {"upper","lower"})
        self._ks: Dict[tuple, float] = {}

    # ── seeding / registration ────────────────────────────────────────────

    def seed_metric(self, metric: str, init_mean: float):
        if metric not in self._metrics:
            init_std = max(self.initial_std_ratio * abs(init_mean), 1e-6)
            self._metrics[metric] = MetricStats(init_mean, init_std, self._forget_alpha)

    def register_bound(self, rule: str, metric: str, anchor: float, direction: str):
        """Register an adaptive boundary; metric must already be seeded."""
        stats = self._metrics.get(metric)
        if stats is None:
            return
        if direction == "upper":
            k = (anchor - stats.mean) / stats.std if stats.std > 0 else 0.0
        else:
            k = (stats.mean - anchor) / stats.std if stats.std > 0 else 0.0
        self._ks[(rule, metric, anchor, direction)] = max(k, 0.0)

    # ── public API used by rules ─────────────────────────────────────────

    def bound(self, rule: str, metric: str, anchor: float, direction: str) -> float:
        """Effective boundary for a rule on a metric (anchor when not adaptive)."""
        if not self.adaptive:
            return anchor
        stats = self._metrics.get(metric)
        if stats is None or stats.n < self.burn_in:
            return anchor
        key = (rule, metric, anchor, direction)
        k = self._ks.get(key, 3.0)
        if direction == "upper":
            b = stats.mean + k * stats.std
        else:
            b = stats.mean - k * stats.std
        lo = self.clamp_min * anchor
        hi = self.clamp_max * anchor
        return max(min(b, hi), lo)

    def rule_scale(self, rule: str) -> float:
        """Multiplier applied to a rule's risk scores (1.0 when not adaptive)."""
        if not self.adaptive:
            return 1.0
        beta = self._betas.get(rule)
        if beta is None or beta.evidence < self.burn_in:
            return 1.0
        adapt_w = min(1.0, beta.evidence / self.burn_in)
        scale = 1.0 - adapt_w * (1.0 - beta.mean)
        return max(scale, self.posterior_min)

    def update_normal_metric(self, metric: str, value: float):
        if not self.adaptive:
            return
        stats = self._metrics.get(metric)
        if stats is not None:
            stats.update(float(value))

    def update_beta(self, rule: str, tp: bool = False, fp: bool = False):
        if not self.adaptive:
            return
        beta = self._betas.setdefault(rule, BetaPosterior())
        beta.update(tp=tp, fp=fp)

    # ── persistence ───────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "adaptive": self.adaptive,
            "metrics": {m: s.to_dict() for m, s in self._metrics.items()},
            "betas": {r: b.to_dict() for r, b in self._betas.items()},
            "ks": {f"{r}|{m}|{a}|{d}": k for (r, m, a, d), k in self._ks.items()},
        }

    def load_state(self, state: dict):
        if not state:
            return
        self.adaptive = bool(state.get("adaptive", self.adaptive))
        for m, s in (state.get("metrics") or {}).items():
            self._metrics[m] = MetricStats.from_dict(s, self._forget_alpha)
        for r, b in (state.get("betas") or {}).items():
            self._betas[r] = BetaPosterior.from_dict(b)
        for key, k in (state.get("ks") or {}).items():
            parts = key.split("|")
            if len(parts) == 4:
                self._ks[(parts[0], parts[1], float(parts[2]), parts[3])] = float(k)
