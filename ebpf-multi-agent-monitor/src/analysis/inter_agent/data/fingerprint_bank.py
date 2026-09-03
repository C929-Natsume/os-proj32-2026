"""Communication fingerprint bank (Stage A).

Learns per-channel profiles of inter-agent traffic from normal observations
and scores live traffic for deviation. A "channel" is the directed pair
(src, dst, type); each channel keeps an EWMA mean/variance of the per-window
``msg_count`` (plus ``weight`` / ``data_size``) seen during normal operation.

Stage A scope (fully local):
  - online EWMA channel statistics
  - JSON persistence (``save`` / ``load`` / ``to_dict`` / ``from_dict``)
  - per-channel deviation scoring (z-score on observed vs expected msg_count)
  - unknown-channel penalty (a previously unseen src/dst/type is a strong
    deviation signal) and per-event magnitude deviation on known channels
  - channel-level report that can be fused by the monitor as a supplemental
    edge/node risk

Stage B (deferred): temporal sequence embeddings of channel activity.

All learning/scoring is CPU-only and the module is a no-op when disabled.
"""

import json
import logging
import math
import os
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ChannelStats:
    """EWMA statistics for one (src, dst, type) channel."""

    def __init__(self, src: str, dst: str, ctype: str,
                 forget_alpha: float = 0.1):
        self.src = str(src)
        self.dst = str(dst)
        self.type = str(ctype)
        self.forget_alpha = float(forget_alpha)
        self.msg_mean = 0.0
        self.msg_var = 1.0
        self.weight_mean = 0.0
        self.weight_var = 1.0
        self.data_mean = 0.0
        self.data_var = 1.0
        self.n = 0.0
        self.first_seen_ns = None
        self.last_seen_ns = None

    def update(self, event: dict):
        msg = float(event.get("msg_count", 0))
        weight = float(event.get("weight", 0.5))
        data = float(event.get("data_size", 0))
        a = self.forget_alpha
        if self.n == 0.0:
            self.msg_mean, self.msg_var = msg, 1.0
            self.weight_mean, self.weight_var = weight, 1.0
            self.data_mean, self.data_var = data, 1.0
        else:
            self.msg_mean, self.msg_var = self._ewma(
                self.msg_mean, self.msg_var, msg, a)
            self.weight_mean, self.weight_var = self._ewma(
                self.weight_mean, self.weight_var, weight, a)
            self.data_mean, self.data_var = self._ewma(
                self.data_mean, self.data_var, data, a)
        self.n += 1.0
        ts = event.get("timestamp_ns")
        if self.first_seen_ns is None:
            self.first_seen_ns = ts
        if ts is not None:
            self.last_seen_ns = ts

    @staticmethod
    def _ewma(mean: float, var: float, value: float, a: float):
        new_mean = mean + a * (value - mean)
        new_var = (1.0 - a) * (var + a * (value - mean) ** 2)
        if new_var < 1e-6:
            new_var = 1e-6
        return new_mean, new_var

    @property
    def msg_std(self) -> float:
        return math.sqrt(self.msg_var)

    def z_score(self, msg_count: float) -> float:
        """Standardised deviation of a window's msg_count from the envelope."""
        if self.n < 1.0:
            return 0.0
        std = self.msg_std
        if std < 1e-3:
            # near-constant channel: relative deviation
            base = max(abs(self.msg_mean), 1.0)
            return (msg_count - self.msg_mean) / base
        return (msg_count - self.msg_mean) / std

    def to_dict(self) -> dict:
        return {
            "src": self.src, "dst": self.dst, "type": self.type,
            "msg_mean": self.msg_mean, "msg_var": self.msg_var,
            "weight_mean": self.weight_mean, "weight_var": self.weight_var,
            "data_mean": self.data_mean, "data_var": self.data_var,
            "n": self.n,
            "first_seen_ns": self.first_seen_ns,
            "last_seen_ns": self.last_seen_ns,
        }

    @classmethod
    def from_dict(cls, d: dict, forget_alpha: float = 0.1) -> "ChannelStats":
        cs = cls(d["src"], d["dst"], d["type"], forget_alpha)
        cs.msg_mean = float(d.get("msg_mean", 0.0))
        cs.msg_var = max(float(d.get("msg_var", 1.0)), 1e-6)
        cs.weight_mean = float(d.get("weight_mean", 0.0))
        cs.weight_var = max(float(d.get("weight_var", 1.0)), 1e-6)
        cs.data_mean = float(d.get("data_mean", 0.0))
        cs.data_var = max(float(d.get("data_var", 1.0)), 1e-6)
        cs.n = float(d.get("n", 0.0))
        cs.first_seen_ns = d.get("first_seen_ns")
        cs.last_seen_ns = d.get("last_seen_ns")
        return cs


def _z_to_risk(z: float, max_risk: float = 1.0) -> float:
    """Map a z-score to a [0, 1] risk, soft threshold at z >= 2."""
    if z <= 1.0:
        return 0.0
    return min((z - 1.0) / 2.0, 1.0) * max_risk


class CommunicationFingerprintBank:
    """Per-channel traffic fingerprinting + deviation scoring.

    ``enabled=False`` makes every method a no-op so the monitor is untouched
    unless explicitly switched on.
    """

    def __init__(self, enabled: bool = False,
                 forget_alpha: float = 0.1,
                 z_threshold: float = 3.0,
                 min_samples: int = 5,
                 unknown_penalty: float = 1.0,
                 magnitude_scale: float = 2.0,
                 save_path: Optional[str] = None):
        self.enabled = bool(enabled)
        self.forget_alpha = float(forget_alpha)
        self.z_threshold = float(z_threshold)
        self.min_samples = float(min_samples)
        self.unknown_penalty = float(unknown_penalty)
        self.magnitude_scale = float(magnitude_scale)
        self.save_path = save_path
        self._channels: Dict[tuple, ChannelStats] = {}

    # ── aggregation ───────────────────────────────────────────────────────

    @staticmethod
    def _aggregate(interactions):
        """Per-channel per-window aggregates.

        Returns {key: (window_msg, weight, data, n_events)} where
        ``window_msg`` is the total msg_count on the channel during the
        window, ``weight`` the mean event weight and ``data`` the max
        data_size.
        """
        agg: Dict[tuple, list] = {}
        for e in interactions or []:
            src, dst = e.get("src"), e.get("dst")
            ctype = e.get("type", "message")
            if not src or not dst:
                continue
            key = (str(src), str(dst), str(ctype))
            cur = agg.get(key)
            if cur is None:
                cur = [0.0, 0.0, 0.0, 0]
                agg[key] = cur
            cur[0] += float(e.get("msg_count", 0))
            cur[1] += float(e.get("weight", 0.5))
            cur[2] = max(cur[2], float(e.get("data_size", 0)))
            cur[3] += 1
        out = {}
        for key, (msg, wsum, data, n) in agg.items():
            out[key] = (msg, wsum / max(n, 1), data, n)
        return out

    # ── learning ──────────────────────────────────────────────────────────

    def learn(self, interactions: Optional[List[dict]]) -> int:
        """Record one observation window's channels into the bank.

        Returns the number of channels updated (0 when disabled).
        """
        if not self.enabled or not interactions:
            return 0
        updated = 0
        for key, (msg, weight, data, n_events) in self._aggregate(interactions).items():
            cs = self._channels.get(key)
            if cs is None:
                cs = ChannelStats(key[0], key[1], key[2], self.forget_alpha)
                self._channels[key] = cs
            cs.update({
                "src": key[0], "dst": key[1], "type": key[2],
                "msg_count": msg, "weight": weight, "data_size": data,
            })
            updated += 1
        return updated

    # ── scoring ───────────────────────────────────────────────────────────

    def score(self, interactions: Optional[List[dict]]) -> dict:
        """Deviation report over one observation window.

        Returns a dict with per-channel risks, an overall risk and the
        unknown-channel count. Empty report (risk 0) when disabled or when
        the bank has not seen enough normal traffic.
        """
        if not self.enabled:
            return self._empty_report()
        channels: Dict[str, float] = {}
        magnitude: Dict[str, float] = {}
        unknown = 0
        agg = self._aggregate(interactions)

        for key, (msg, weight, data, n_events) in agg.items():
            ckey = f"{key[0]}->{key[1]}::{key[2]}"
            cs = self._channels.get(key)
            if cs is None or cs.n < self.min_samples:
                unknown += 1
                channels[ckey] = self.unknown_penalty
                continue
            z = cs.z_score(msg)
            risk = _z_to_risk(z, max_risk=1.0)
            # magnitude deviation on weight / data_size of the window
            mag = 0.0
            for attr, mean, var in (
                    ("weight", cs.weight_mean, cs.weight_var),
                    ("data_size", cs.data_mean, cs.data_var)):
                v = weight if attr == "weight" else data
                std = math.sqrt(max(var, 1e-6))
                if std < 1e-3:
                    dz = (v - mean) / max(abs(mean), 1.0)
                else:
                    dz = (v - mean) / std
                if dz > 1.0:
                    mag = max(mag, _z_to_risk(dz, max_risk=1.0))
            channels[ckey] = min(risk + mag * 0.5, 1.0)
            magnitude[ckey] = mag

        risk = max(channels.values()) if channels else 0.0
        chi2 = 0.0
        dof = 0
        for key, (msg, *_rest) in agg.items():
            cs = self._channels.get(key)
            if cs is None or cs.n < self.min_samples:
                continue
            if cs.msg_var > 1e-6:
                chi2 += (msg - cs.msg_mean) ** 2 / cs.msg_var
                dof += 1
        return {
            "channels": channels,
            "magnitude": magnitude,
            "unknown_channels": unknown,
            "n_live": len(agg),
            "risk": float(risk),
            "chi2": float(chi2),
            "dof": dof,
        }

    @staticmethod
    def _empty_report() -> dict:
        return {"channels": {}, "magnitude": {}, "unknown_channels": 0,
                "n_live": 0, "risk": 0.0, "chi2": 0.0, "dof": 0}

    # ── introspection ─────────────────────────────────────────────────────

    def channel_summary(self) -> List[dict]:
        out = []
        for key, cs in self._channels.items():
            out.append({
                "channel": f"{key[0]}->{key[1]}::{key[2]}",
                "n": cs.n, "msg_mean": cs.msg_mean, "msg_std": cs.msg_std,
            })
        out.sort(key=lambda d: -d["n"])
        return out

    def reset(self):
        self._channels.clear()

    # ── persistence ───────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "forget_alpha": self.forget_alpha,
            "z_threshold": self.z_threshold,
            "min_samples": self.min_samples,
            "unknown_penalty": self.unknown_penalty,
            "magnitude_scale": self.magnitude_scale,
            "channels": [cs.to_dict() for cs in self._channels.values()],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CommunicationFingerprintBank":
        bank = cls(
            enabled=True,
            forget_alpha=float(d.get("forget_alpha", 0.1)),
            z_threshold=float(d.get("z_threshold", 3.0)),
            min_samples=float(d.get("min_samples", 5)),
            unknown_penalty=float(d.get("unknown_penalty", 1.0)),
            magnitude_scale=float(d.get("magnitude_scale", 2.0)),
        )
        for cd in d.get("channels", []):
            cs = ChannelStats.from_dict(cd, bank.forget_alpha)
            bank._channels[(cs.src, cs.dst, cs.type)] = cs
        return bank

    def save(self, path: Optional[str] = None) -> bool:
        path = path or self.save_path
        if not path:
            return False
        try:
            d = os.path.dirname(os.path.abspath(path))
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.warning("Failed to save fingerprint bank: %s", e)
            return False

    def load(self, path: Optional[str] = None) -> bool:
        path = path or self.save_path
        if not path or not os.path.isfile(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            bank = self.from_dict(d)
            self._channels = bank._channels
            return True
        except Exception as e:
            logger.warning("Failed to load fingerprint bank: %s", e)
            return False
