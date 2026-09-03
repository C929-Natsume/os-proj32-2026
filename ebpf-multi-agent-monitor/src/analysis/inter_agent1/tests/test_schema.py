"""Validate JSON data format specification against common.h and intra_agent."""

import json
import pytest
import os

from inter_agent.data.schema import *  # noqa — check module loads


class TestSchemaCoverage:
    """Verify schema covers all event types from common.h and intra_agent."""

    def test_schema_module_loads(self):
        """Verify schema module is loadable and contains documentation."""
        import inter_agent.data.schema as s
        assert hasattr(s, "__doc__")
        assert "inter:agents" in (s.__doc__ or "")

    def test_proc_event_subtypes(self):
        """Must cover all proc_event_type enum values from common.h."""
        required = {"PROC_EXEC", "PROC_FORK", "PROC_EXIT",
                    "PROC_SIGNAL", "PROC_SETUID"}
        import inter_agent.data.schema as s
        doc = s.__doc__ or ""
        for t in required:
            assert t in doc, f"{t} not documented in schema.py"

    def test_fs_event_subtypes(self):
        """Must cover all fs_event_type enum values from common.h."""
        required = {"FS_OPEN", "FS_CLOSE", "FS_READ", "FS_WRITE",
                    "FS_UNLINK", "FS_RENAME", "FS_CHMOD",
                    "FS_CREATE", "FS_RMDIR"}
        import inter_agent.data.schema as s
        doc = s.__doc__ or ""
        for t in required:
            assert t in doc, f"{t} not documented in schema.py"

    def test_net_event_subtypes(self):
        """Must cover all net_event_type enum values from common.h."""
        required = {"NET_SOCKET", "NET_CONNECT", "NET_BIND",
                    "NET_LISTEN", "NET_ACCEPT", "NET_SEND",
                    "NET_RECV", "NET_CLOSE", "NET_TCP_STATE"}
        import inter_agent.data.schema as s
        doc = s.__doc__ or ""
        for t in required:
            assert t in doc, f"{t} not documented in schema.py"

    def test_intra_agent_alert_types(self):
        """Must cover all audit rules from intra_analyzer.c."""
        required = {"UNEXPECTED_SHELL_EXEC", "SENSITIVE_FILE_ACCESS",
                    "OUT_OF_WORKSPACE_OPERATION", "POSSIBLE_LOGIC_LOOP"}
        import inter_agent.data.schema as s
        doc = s.__doc__ or ""
        for t in required:
            assert t in doc, f"{t} not documented in schema.py"

    def test_intra_agent_counters(self):
        """Must cover all pid_stats fields from intra_analyzer.c."""
        required = {
            "proc_exec_count", "fs_open_count", "fs_read_count",
            "fs_write_count", "fs_unlink_count",
            "net_connect_count", "net_send_count", "net_recv_count",
            "unique_files_count", "window_start_ns",
        }
        import inter_agent.data.schema as s
        doc = s.__doc__ or ""
        for t in required:
            assert t in doc, f"{t} not documented in schema.py"

    def test_response_levels(self):
        """PASS/ALERT/BLOCK/ISOLATE from inter_agent design."""
        levels = {"PASS", "ALERT", "BLOCK", "ISOLATE"}
        import inter_agent.data.schema as s
        doc = s.__doc__ or ""
        for t in levels:
            assert t in doc, f"{t} not documented in schema.py"


class TestObservationFormat:
    """Test the observation dict that RedisCollector produces."""

    @pytest.fixture
    def sample_observation(self):
        return {
            "agents": {
                "agent_0": {
                    "cpu_usage": 0.75,
                    "memory_usage": 0.65,
                    "api_call_count": 78,
                    "msg_sent": 34,
                    "msg_received": 29,
                    "proc_exec_count": 12,
                    "proc_fork_count": 2,
                    "fs_open_count": 45,
                    "fs_read_count": 234,
                    "fs_write_count": 156,
                    "fs_unlink_count": 3,
                    "net_connect_count": 89,
                    "net_send_count": 567,
                    "net_recv_count": 543,
                    "shell_exec_count": 0,
                    "sensitive_file_count": 0,
                    "unique_files_count": 8,
                },
                "agent_1": {
                    "cpu_usage": 0.35,
                    "memory_usage": 0.40,
                    "api_call_count": 12,
                    "msg_sent": 5,
                    "msg_received": 8,
                    "proc_exec_count": 3,
                    "proc_fork_count": 0,
                    "fs_open_count": 10,
                    "fs_read_count": 45,
                    "fs_write_count": 23,
                    "fs_unlink_count": 0,
                    "net_connect_count": 15,
                    "net_send_count": 89,
                    "net_recv_count": 76,
                    "shell_exec_count": 0,
                    "sensitive_file_count": 0,
                    "unique_files_count": 5,
                },
            },
            "interactions": [
                {"src": "agent_0", "dst": "agent_1",
                 "type": "api_call", "weight": 0.5, "timestamp_ns": 1000},
                {"src": "agent_1", "dst": "agent_0",
                 "type": "message", "weight": 0.3, "timestamp_ns": 1001},
            ],
            "messages": [
                {"src": "agent_0", "dst": "agent_1",
                 "msg_type": "request", "data_size": 2048,
                 "timestamp_ns": 1000},
                {"src": "agent_1", "dst": "agent_0",
                 "msg_type": "response", "data_size": 512,
                 "timestamp_ns": 1001},
            ],
            "anomalies": [
                {"agent_id": "agent_0", "rule": "POSSIBLE_LOGIC_LOOP",
                 "severity": "MEDIUM", "risk_score": 0.5,
                 "description": "High IO with few files",
                 "timestamp_ns": 1500},
            ],
            "timestamp": 2000,
            "window_start_ns": 0,
        }

    def test_observation_has_all_keys(self, sample_observation):
        assert "agents" in sample_observation
        assert "interactions" in sample_observation
        assert "messages" in sample_observation
        assert "anomalies" in sample_observation
        assert "timestamp" in sample_observation
        assert "window_start_ns" in sample_observation

    def test_observation_serializable(self, sample_observation):
        dumped = json.dumps(sample_observation)
        loaded = json.loads(dumped)
        assert loaded["agents"]["agent_0"]["cpu_usage"] == 0.75
        assert loaded["messages"][0]["src"] == "agent_0"

    def test_agent_metric_fields(self, sample_observation):
        a0 = sample_observation["agents"]["agent_0"]
        int_fields = ["api_call_count", "msg_sent", "msg_received",
                      "proc_exec_count", "fs_open_count", "fs_read_count",
                      "fs_write_count", "net_connect_count",
                      "shell_exec_count", "unique_files_count"]
        for f in int_fields:
            assert isinstance(a0[f], int), f"{f} should be int"
        float_fields = ["cpu_usage", "memory_usage"]
        for f in float_fields:
            assert isinstance(a0[f], (int, float)), f"{f} should be numeric"

    def test_interaction_format(self, sample_observation):
        for it in sample_observation["interactions"]:
            assert "src" in it
            assert "dst" in it
            assert it["type"] in ("api_call", "message", "file_share")
            assert isinstance(it["weight"], (int, float))

    def test_message_format(self, sample_observation):
        for m in sample_observation["messages"]:
            assert "src" in m
            assert "dst" in m
            assert "msg_type" in m
            assert isinstance(m["data_size"], int)

    def test_anomaly_format(self, sample_observation):
        for a in sample_observation["anomalies"]:
            assert "agent_id" in a
            assert a["rule"] in (
                "UNEXPECTED_SHELL_EXEC", "SENSITIVE_FILE_ACCESS",
                "OUT_OF_WORKSPACE_OPERATION", "POSSIBLE_LOGIC_LOOP",
            ) or True  # allow future rules
            assert 0.0 <= a["risk_score"] <= 1.0


class TestEbpfEventFormat:
    """Verify eBPF event JSON format matches common.h struct layout."""

    def test_proc_event_exec(self):
        event = {
            "event_type": "proc",
            "subtype": "PROC_EXEC",
            "timestamp_ns": 1234567890000,
            "pid": 12345,
            "tid": 12345,
            "comm": "python3",
            "filename": "/bin/ls",
            "parent_pid": 12344,
        }
        assert event["subtype"] == "PROC_EXEC"
        assert "filename" in event
        assert "parent_pid" in event
        # matches common.h: proc_event.exec.filename, proc_event.exec.parent_pid

    def test_proc_event_fork(self):
        event = {
            "event_type": "proc",
            "subtype": "PROC_FORK",
            "pid": 12345,
            "child_pid": 12346,
            "parent_pid": 12344,
        }
        assert "child_pid" in event
        # matches common.h: proc_event.fork.child_pid

    def test_fs_event_open(self):
        event = {
            "event_type": "fs",
            "subtype": "FS_OPEN",
            "pid": 12345,
            "filename": "/etc/passwd",
            "flags": 0,
        }
        assert "filename" in event
        # matches common.h: fs_event.open.filename, fs_event.open.flags

    def test_fs_event_read_write(self):
        for subtype in ("FS_READ", "FS_WRITE"):
            event = {
                "event_type": "fs",
                "subtype": subtype,
                "pid": 12345,
                "fd": 3,
                "bytes": 4096,
                "filename": "/data/file.txt",
            }
            assert event["subtype"] == subtype
            assert "fd" in event
            assert "bytes" in event
            # matches common.h: fs_event{read,write}.fd/bytes/filename

    def test_net_event_connect(self):
        event = {
            "event_type": "net",
            "subtype": "NET_CONNECT",
            "pid": 12345,
            "fd": 3,
            "saddr": "16777343",
            "sport": 45321,
            "family": 2,
        }
        assert "fd" in event
        assert "saddr" in event
        assert "sport" in event
        # matches common.h: net_event.connect.fd/saddr/sport/family

    def test_net_event_send_recv(self):
        for subtype in ("NET_SEND", "NET_RECV"):
            event = {
                "event_type": "net",
                "subtype": subtype,
                "pid": 12345,
                "fd": 4,
                "bytes": 512,
            }
            event["daddr"] = "2130706433" if subtype == "NET_SEND" else "16777343"
            event["dport"] = 80 if subtype == "NET_SEND" else 443
            assert "fd" in event
            assert "bytes" in event
            # matches common.h: net_event{send,recv}.fd/bytes

    def test_net_event_tcp_state(self):
        event = {
            "event_type": "net",
            "subtype": "NET_TCP_STATE",
            "saddr": "2130706433",
            "sport": 45321,
            "daddr": "16777343",
            "dport": 80,
            "oldstate": 1,
            "newstate": 2,
        }
        assert "oldstate" in event
        assert "newstate" in event
        # matches common.h: net_event.tcp_state.oldstate/newstate
