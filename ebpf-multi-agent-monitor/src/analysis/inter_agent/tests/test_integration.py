"""Integration tests for the full detection pipeline with Redis-format data."""

import pytest
import os

from inter_agent.monitor.agent import MonitorAgent, ResponseLevel
from inter_agent.config.loader import load_config


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def normal_obs():
    return {
        "agents": {
            "agent_0": {"cpu_usage": 0.3, "memory_usage": 0.4,
                        "api_call_count": 10, "msg_sent": 3, "msg_received": 2,
                        "proc_exec_count": 1, "proc_fork_count": 0,
                        "fs_open_count": 5, "fs_read_count": 20,
                        "fs_write_count": 10, "fs_unlink_count": 0,
                        "net_connect_count": 8, "net_send_count": 30,
                        "net_recv_count": 25, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 5},
            "agent_1": {"cpu_usage": 0.25, "memory_usage": 0.35,
                        "api_call_count": 5, "msg_sent": 3, "msg_received": 2,
                        "proc_exec_count": 0, "proc_fork_count": 0,
                        "fs_open_count": 3, "fs_read_count": 15,
                        "fs_write_count": 8, "fs_unlink_count": 0,
                        "net_connect_count": 5, "net_send_count": 20,
                        "net_recv_count": 18, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 4},
        },
        "interactions": [
            {"src": "agent_0", "dst": "agent_1", "type": "message",
             "weight": 0.3, "timestamp_ns": 100},
        ],
        "messages": [
            {"src": "agent_0", "dst": "agent_1", "msg_type": "request",
             "data_size": 256, "timestamp_ns": 100},
        ],
        "anomalies": [],
        "timestamp": 200,
        "window_start_ns": 0,
    }


@pytest.fixture
def resource_anomaly_obs():
    """CPU/memory exceed thresholds (intra_agent resource anomaly pattern)."""
    return {
        "agents": {
            "agent_0": {"cpu_usage": 0.95, "memory_usage": 0.90,
                        "api_call_count": 80, "msg_sent": 40, "msg_received": 30,
                        "proc_exec_count": 10, "proc_fork_count": 2,
                        "fs_open_count": 40, "fs_read_count": 200,
                        "fs_write_count": 150, "fs_unlink_count": 5,
                        "net_connect_count": 60, "net_send_count": 400,
                        "net_recv_count": 350, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 10},
            "agent_1": {"cpu_usage": 0.30, "memory_usage": 0.35,
                        "api_call_count": 5, "msg_sent": 2, "msg_received": 3,
                        "proc_exec_count": 0, "proc_fork_count": 0,
                        "fs_open_count": 3, "fs_read_count": 15,
                        "fs_write_count": 8, "fs_unlink_count": 0,
                        "net_connect_count": 5, "net_send_count": 20,
                        "net_recv_count": 18, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 4},
        },
        "interactions": [
            {"src": "agent_0", "dst": "agent_1", "type": "api_call",
             "weight": 0.9, "timestamp_ns": 100},
        ],
        "messages": [],
        "anomalies": [],
        "timestamp": 200,
        "window_start_ns": 0,
    }


@pytest.fixture
def security_anomaly_obs():
    """Shell exec + sensitive file access (intra_agent security pattern)."""
    return {
        "agents": {
            "agent_0": {"cpu_usage": 0.45, "memory_usage": 0.50,
                        "api_call_count": 30, "msg_sent": 10, "msg_received": 8,
                        "proc_exec_count": 5, "proc_fork_count": 1,
                        "fs_open_count": 20, "fs_read_count": 80,
                        "fs_write_count": 40, "fs_unlink_count": 2,
                        "net_connect_count": 25, "net_send_count": 100,
                        "net_recv_count": 90, "shell_exec_count": 1,
                        "sensitive_file_count": 1, "unique_files_count": 8},
            "agent_1": {"cpu_usage": 0.30, "memory_usage": 0.35,
                        "api_call_count": 5, "msg_sent": 2, "msg_received": 3,
                        "proc_exec_count": 0, "proc_fork_count": 0,
                        "fs_open_count": 3, "fs_read_count": 15,
                        "fs_write_count": 8, "fs_unlink_count": 0,
                        "net_connect_count": 5, "net_send_count": 20,
                        "net_recv_count": 18, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 4},
        },
        "interactions": [
            {"src": "agent_0", "dst": "agent_1", "type": "api_call",
             "weight": 0.6, "timestamp_ns": 100},
        ],
        "messages": [],
        "anomalies": [
            {"agent_id": "agent_0", "rule": "UNEXPECTED_SHELL_EXEC",
             "severity": "HIGH", "risk_score": 0.9,
             "description": "Shell exec detected",
             "timestamp_ns": 150},
            {"agent_id": "agent_0", "rule": "SENSITIVE_FILE_ACCESS",
             "severity": "HIGH", "risk_score": 0.85,
             "description": "Sensitive file accessed",
             "timestamp_ns": 160},
        ],
        "timestamp": 200,
        "window_start_ns": 0,
    }


class TestPipeline:
    def test_normal_pipeline(self, normal_obs, config):
        model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                  "models", "anomaly_detector.pth")
        agent = MonitorAgent(config, model_path=model_path)
        assert agent._gnn_detector.is_loaded, "Pretrained model must load"
        report = agent.process_observation(normal_obs)
        assert isinstance(report.max_risk, float)
        assert report.max_risk >= 0.0
        assert isinstance(report.response_level, ResponseLevel)

    def test_resource_anomaly(self, resource_anomaly_obs, config):
        model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                  "models", "anomaly_detector.pth")
        agent = MonitorAgent(config, model_path=model_path)
        report = agent.process_observation(resource_anomaly_obs)
        assert report.max_risk > 0.5
        assert report.response_level in (ResponseLevel.ALERT,
                                         ResponseLevel.BLOCK,
                                         ResponseLevel.ISOLATE)

    def test_security_anomaly(self, security_anomaly_obs, config):
        model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                  "models", "anomaly_detector.pth")
        agent = MonitorAgent(config, model_path=model_path)
        report = agent.process_observation(security_anomaly_obs)
        assert report.max_risk > 0.7
        assert "agent_0" in report.anomalous_nodes
        assert report.source_agent == "agent_0"

    def test_report_structure(self, normal_obs, config):
        model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                  "models", "anomaly_detector.pth")
        agent = MonitorAgent(config, model_path=model_path)
        r = agent.process_observation(normal_obs)
        assert hasattr(r, "timestamp_ns")
        assert hasattr(r, "response_level")
        assert hasattr(r, "max_risk")
        assert hasattr(r, "anomalous_nodes")
        assert hasattr(r, "anomalous_edges")
        assert hasattr(r, "state_view")
        assert "risk_scores" in r.state_view
        assert "response" in r.state_view

    def test_multiple_observations(self, normal_obs, config):
        agent = MonitorAgent(config)
        for _ in range(3):
            agent.process_observation(normal_obs)
        assert agent._last_report is not None

    def test_clear(self, normal_obs, config):
        agent = MonitorAgent(config)
        agent.process_observation(normal_obs)
        agent.clear()
        assert agent._last_report is None

    def test_config_loading(self, config):
        assert "redis" in config
        assert "detection" in config
        assert "agents" in config
        assert config["redis"]["host"] == "127.0.0.1"
        assert config["detection"]["cpu_usage_max"] == 0.8

    def test_gnn_model_loaded(self, tmp_path, config):
        from inter_agent.detection.gnn_detector import DOMINANT, AnomalyClassifier
        import torch
        import numpy as np
        model_path = os.path.join(str(tmp_path), "test_model.pth")
        model = DOMINANT(in_dim=30, edge_dim=6)
        classifier = AnomalyClassifier(latent_dim=64)
        torch.save({
            "model_state_dict": model.state_dict(),
            "classifier_state_dict": classifier.state_dict(),
            "args": {},
        }, model_path)
        assert os.path.isfile(model_path), f"Model file not found at {model_path}"
        agent = MonitorAgent(config, model_path=model_path)
        assert agent._gnn_detector.is_loaded, (
            f"Model not loaded. Check logs. "
            f"model_path={model_path}, exists={os.path.isfile(model_path)}"
        )

    def test_gnn_inference_with_model(self, tmp_path, config, normal_obs):
        from inter_agent.detection.gnn_detector import DOMINANT, AnomalyClassifier
        import torch
        model_path = os.path.join(tmp_path, "test_model.pth")
        model = DOMINANT(in_dim=30, edge_dim=6)
        classifier = AnomalyClassifier(latent_dim=64)
        torch.save({
            "model_state_dict": model.state_dict(),
            "classifier_state_dict": classifier.state_dict(),
            "args": {},
        }, model_path)
        agent = MonitorAgent(config, model_path=str(model_path))
        report = agent.process_observation(normal_obs)
        assert len(report.gnn_risks) > 0
        for aid, risk in report.gnn_risks.items():
            assert isinstance(risk, float)
            assert 0.0 <= risk <= 1.0


def test_fingerprint_disabled_by_default(config, normal_obs):
    """Default config must keep fingerprint_result empty (zero regression)."""
    agent = MonitorAgent(config)
    report = agent.process_observation(normal_obs)
    assert report.fingerprint_result == {}


def test_fingerprint_enabled_learns_and_flags_storm(config, normal_obs):
    cfg = config
    cfg.setdefault("detection", {})["fingerprint"] = {
        "enabled": True, "min_samples": 2, "z_threshold": 3.0,
        "weight": 0.2,
    }
    # Disable GNN: its scores on the "clean" window are model/env-dependent and
    # could block the learn gate; the fingerprint logic itself must be tested
    # against the deterministic rule/semantic modules only.
    cfg["model"]["model_path"] = None
    agent = MonitorAgent(cfg)
    # semantically clean window (low net_send so no soft semantic rules fire)
    clean_obs = {
        "agents": {
            "agent_0": {"cpu_usage": 0.3, "memory_usage": 0.4,
                        "api_call_count": 10, "msg_sent": 3, "msg_received": 2,
                        "proc_exec_count": 1, "proc_fork_count": 0,
                        "fs_open_count": 5, "fs_read_count": 20,
                        "fs_write_count": 10, "fs_unlink_count": 0,
                        "net_connect_count": 8, "net_send_count": 5,
                        "net_recv_count": 4, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 5},
            "agent_1": {"cpu_usage": 0.25, "memory_usage": 0.35,
                        "api_call_count": 5, "msg_sent": 3, "msg_received": 2,
                        "proc_exec_count": 0, "proc_fork_count": 0,
                        "fs_open_count": 3, "fs_read_count": 15,
                        "fs_write_count": 8, "fs_unlink_count": 0,
                        "net_connect_count": 5, "net_send_count": 3,
                        "net_recv_count": 2, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 4},
        },
        "interactions": [
            {"src": "agent_0", "dst": "agent_1", "type": "message",
             "msg_count": 2, "data_size": 256, "timestamp_ns": 100},
        ],
        "messages": [],
        "anomalies": [],
        "timestamp": 200,
        "window_start_ns": 0,
    }
    # learn the normal profile over several clean windows (warm-up first)
    for _ in range(3):
        agent.process_observation(clean_obs)
    for _ in range(3):
        report = agent.process_observation(clean_obs)
        assert report.fingerprint_result["risk"] < 0.5
    # sudden flood on a channel that was near-silent must be flagged
    flood_obs = dict(clean_obs)
    flood_obs["interactions"] = [
        {"src": "agent_0", "dst": "agent_1", "type": "message",
         "msg_count": 500, "data_size": 256, "timestamp_ns": 100},
    ]
    report = agent.process_observation(flood_obs)
    assert report.fingerprint_result["risk"] > 0.5
