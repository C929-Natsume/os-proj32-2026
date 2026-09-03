"""Test detection modules with Redis-format observation data."""

import pytest
import os

from inter_agent.detection.gnn_detector import RuleBasedDetector

from inter_agent.detection.message_detector import MessageAnomalyDetector

from inter_agent.detection.propagation_analyzer import PropagationPathAnalyzer

from inter_agent.detection.temporal_detector import TemporalAnomalyDetector

from inter_agent.graph.builder import AgentInteractionGraph

from inter_agent.graph.utterance_graph import UtteranceGraph


@pytest.fixture
def normal_obs():
    return {
        "agents": {
            "agent_0": {"cpu_usage": 0.3, "memory_usage": 0.4,
                        "api_call_count": 10, "msg_sent": 3, "msg_received": 2,
                        "proc_exec_count": 1, "fs_open_count": 5,
                        "fs_read_count": 20, "fs_write_count": 10,
                        "net_connect_count": 8, "net_send_count": 30,
                        "net_recv_count": 25, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 5},
            "agent_1": {"cpu_usage": 0.25, "memory_usage": 0.35,
                        "api_call_count": 5, "msg_sent": 2, "msg_received": 3,
                        "proc_exec_count": 0, "fs_open_count": 3,
                        "fs_read_count": 15, "fs_write_count": 8,
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
def anomalous_obs():
    """Observation with multiple anomaly triggers (aligned with intra_agent thresholds)."""
    return {
        "agents": {
            "agent_0": {"cpu_usage": 0.92, "memory_usage": 0.88,
                        "api_call_count": 120, "msg_sent": 80, "msg_received": 60,
                        "proc_exec_count": 15, "fs_open_count": 50,
                        "fs_read_count": 300, "fs_write_count": 200,
                        "net_connect_count": 100, "net_send_count": 600,
                        "net_recv_count": 500, "shell_exec_count": 1,
                        "sensitive_file_count": 1, "unique_files_count": 2},
            "agent_1": {"cpu_usage": 0.35, "memory_usage": 0.40,
                        "api_call_count": 8, "msg_sent": 3, "msg_received": 5,
                        "proc_exec_count": 2, "fs_open_count": 8,
                        "fs_read_count": 30, "fs_write_count": 15,
                        "net_connect_count": 10, "net_send_count": 40,
                        "net_recv_count": 35, "shell_exec_count": 0,
                        "sensitive_file_count": 0, "unique_files_count": 6},
        },
        "interactions": [
            {"src": "agent_0", "dst": "agent_1", "type": "api_call",
             "weight": 0.8, "timestamp_ns": 100},
            {"src": "agent_1", "dst": "agent_0", "type": "message",
             "weight": 0.4, "timestamp_ns": 101},
        ],
        "messages": [
            {"src": "agent_0", "dst": "agent_1", "msg_type": "request",
             "data_size": 4096, "timestamp_ns": 100},
            {"src": "agent_0", "dst": "agent_1", "msg_type": "request",
             "data_size": 2048, "timestamp_ns": 102},
            {"src": "agent_1", "dst": "agent_0", "msg_type": "response",
             "data_size": 512, "timestamp_ns": 103},
        ],
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


class TestRuleBasedDetector:
    def test_normal_no_anomaly(self, normal_obs):
        d = RuleBasedDetector()
        result = d.detect(normal_obs["agents"])
        assert all(s == 0.0 for s in result["scores"].values())

    def test_anomaly_detected(self, anomalous_obs):
        d = RuleBasedDetector()
        result = d.detect(anomalous_obs["agents"])
        a0 = result["scores"]["agent_0"]
        assert a0 > 0.5
        assert result["anomalies"]["agent_0"]

    def test_shell_exec_high_risk(self, anomalous_obs):
        d = RuleBasedDetector()
        result = d.detect(anomalous_obs["agents"])
        assert result["scores"]["agent_0"] >= 0.8

    def test_config_respected(self):
        cfg = {"cpu_usage_max": 0.95, "memory_usage_max": 0.95}
        d = RuleBasedDetector(cfg)
        agents = {"a0": {"cpu_usage": 0.93, "memory_usage": 0.93,
                         "api_call_count": 10, "msg_sent": 5, "msg_received": 3,
                         "shell_exec_count": 0, "sensitive_file_count": 0,
                         "fs_read_count": 10, "fs_write_count": 10,
                         "unique_files_count": 5}}
        result = d.detect(agents)
        assert result["scores"]["a0"] == 0.0


class TestMessageAnomalyDetector:
    def test_normal_no_anomaly(self, normal_obs):
        d = MessageAnomalyDetector()
        d.update_baseline(normal_obs)
        result = d.detect(normal_obs)
        assert result["max_risk"] == 0.0

    def test_anomaly_detected(self, anomalous_obs):
        d = MessageAnomalyDetector(freq_std_threshold=0.5)
        d.update_baseline(anomalous_obs)
        result = d.detect(anomalous_obs)
        assert len(result["anomalies"]) > 0

    def test_intra_anomalies_included(self, anomalous_obs):
        d = MessageAnomalyDetector()
        d.update_baseline(anomalous_obs)
        result = d.detect(anomalous_obs)
        intra_types = [a["type"] for a in result["anomalies"]]
        assert "intra_agent_alert" in intra_types


class TestTemporalAnomalyDetector:
    def test_single_update_no_anomaly(self, normal_obs):
        d = TemporalAnomalyDetector(window_size=5)
        d.update(normal_obs)
        result = d.detect()
        assert all(s == 0.0 for s in result["temporal_scores"].values())

    def test_multiple_updates(self, normal_obs, anomalous_obs):
        d = TemporalAnomalyDetector(window_size=5, risk_threshold=0.3)
        for _ in range(3):
            d.update(normal_obs)
        d.update(anomalous_obs)
        result = d.detect()
        assert result["temporal_scores"].get("agent_0", 0) > 0


class TestPropagationPathAnalyzer:
    def test_no_source_no_propagation(self):
        p = PropagationPathAnalyzer()
        result = p.analyze([], [], None)
        assert result["propagation_paths"] == []

    def test_single_source_propagation(self):
        import networkx as nx
        g = nx.DiGraph()
        g.add_edge("a0", "a1")
        g.add_edge("a1", "a2")
        g.add_edge("a2", "a3")
        p = PropagationPathAnalyzer(max_hops=3)
        p.update_graph(g)
        result = p.analyze(["a0"], [], None)
        assert len(result["propagation_paths"]) > 0
        assert "a0" in result["source_agents"]


class TestGraphBuilder:
    def test_update_from_observation(self, normal_obs):
        g = AgentInteractionGraph()
        g.update_from_observation(normal_obs)
        assert g.node_count == 2
        assert g.graph.has_edge("agent_0", "agent_1")

    def test_clear(self, normal_obs):
        g = AgentInteractionGraph()
        g.update_from_observation(normal_obs)
        assert g.node_count > 0
        g.clear()
        assert g.node_count == 0


class TestUtteranceGraph:
    def test_update_from_observation(self, normal_obs):
        ug = UtteranceGraph()
        ug.update_from_observation(normal_obs)
        assert ug.message_count == 1
        assert ug.get_frequency("agent_0", "agent_1") == 1

    def test_clear(self, normal_obs):
        ug = UtteranceGraph()
        ug.update_from_observation(normal_obs)
        ug.clear()
        assert ug.message_count == 0
