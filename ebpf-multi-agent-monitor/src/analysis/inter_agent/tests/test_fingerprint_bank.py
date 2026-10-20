import json
import os

from inter_agent.data.fingerprint_bank import (
    CommunicationFingerprintBank,
    ChannelStats,
)


def _ev(src, dst, ctype="message", msg=1, weight=0.5, data=10, ts=1):
    return {"src": src, "dst": dst, "type": ctype, "msg_count": msg,
            "weight": weight, "data_size": data, "timestamp_ns": ts}


def _normal_window():
    return [
        _ev("agent_0", "agent_1", "message", msg=5, data=64, ts=1),
        _ev("agent_0", "agent_1", "message", msg=6, data=80, ts=2),
        _ev("agent_1", "agent_2", "api_call", msg=3, weight=0.8, data=32, ts=1),
        _ev("agent_2", "agent_3", "message", msg=4, data=48, ts=1),
    ]


class TestChannelStats:
    def test_learns_envelope(self):
        cs = ChannelStats("a", "b", "message", forget_alpha=0.5)
        for m in (5, 5, 5, 5):
            cs.update(_ev("a", "b", msg=m))
        assert cs.msg_mean == 5.0
        assert cs.n == 4.0
        assert cs.z_score(5.0) == 0.0

    def test_z_score_grows_with_deviation(self):
        cs = ChannelStats("a", "b", "message", forget_alpha=0.3)
        for m in (2, 2, 2, 2):
            cs.update(_ev("a", "b", msg=m))
        z_high = cs.z_score(10)
        z_low = cs.z_score(3)
        assert z_high > z_low
        assert z_high > 1.0

    def test_roundtrip(self):
        cs = ChannelStats("a", "b", "message")
        cs.update(_ev("a", "b", msg=7, data=90, ts=9))
        cs2 = ChannelStats.from_dict(cs.to_dict())
        assert cs2.to_dict() == cs.to_dict()


class TestFingerprintBank:
    def test_disabled_is_noop(self):
        bank = CommunicationFingerprintBank(enabled=False)
        assert bank.learn(_normal_window()) == 0
        assert bank.score(_normal_window())["risk"] == 0.0

    def test_enabled_learns(self):
        bank = CommunicationFingerprintBank(enabled=True, min_samples=1)
        assert bank.learn(_normal_window()) == 3
        assert len(bank.channel_summary()) == 3

    def test_known_channel_low_risk_unknown_high(self):
        bank = CommunicationFingerprintBank(enabled=True, min_samples=2,
                                            z_threshold=3.0)
        normal = _normal_window()
        for _ in range(10):
            bank.learn(normal)
        report = bank.score(normal)
        assert report["unknown_channels"] == 0
        assert report["risk"] < 0.5

        # brand new channel must be flagged as high risk
        report2 = bank.score([_ev("agent_9", "agent_10", "bypass", msg=50)])
        assert report2["unknown_channels"] == 1
        assert report2["risk"] >= 0.9

    def test_message_storm_flagged(self):
        bank = CommunicationFingerprintBank(enabled=True, min_samples=2)
        normal = _normal_window()
        for _ in range(10):
            bank.learn(normal)
        storm = [e for e in normal if e["src"] == "agent_0"]
        storm = [_ev("agent_0", "agent_1", "message", msg=500, data=64)]
        report = bank.score(storm)
        key = "agent_0->agent_1::message"
        assert report["channels"][key] > 0.5

    def test_persistence_roundtrip(self, tmp_path):
        path = os.path.join(str(tmp_path), "bank.json")
        bank = CommunicationFingerprintBank(enabled=True, min_samples=1)
        bank.learn(_normal_window())
        assert bank.save(path) is True
        bank2 = CommunicationFingerprintBank(enabled=True, min_samples=1)
        assert bank2.load(path) is True
        assert bank2.to_dict() == bank.to_dict()
        assert bank2.channel_summary() == bank.channel_summary()

    def test_save_disabled_bank_skips(self, tmp_path):
        bank = CommunicationFingerprintBank(enabled=False)
        assert bank.save(str(tmp_path)) is False

    def test_z_risk_mapping(self):
        from inter_agent.data.fingerprint_bank import _z_to_risk
        assert _z_to_risk(0.5) == 0.0
        assert _z_to_risk(1.0) == 0.0
        assert _z_to_risk(2.0) == 0.5
        assert _z_to_risk(5.0) == 1.0

    def test_learns_real_training_data(self):
        """Bank must run against the actual stored observations."""
        import pytest
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(os.path.dirname(here), "training_data",
                            "val_labeled.json")
        if not os.path.exists(path):
            pytest.skip("training data not present")
        data = json.load(open(path, encoding="utf-8"))
        bank = CommunicationFingerprintBank(enabled=True, min_samples=2)
        for obs in data[:80]:
            bank.learn(obs.get("interactions", []))
        report = bank.score(data[0].get("interactions", []))
        assert report["n_live"] >= 0
        for v in report["channels"].values():
            assert 0.0 <= v <= 1.0
