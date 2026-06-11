#!/usr/bin/env python3
import time

import redis

from .schema import AGENT_METRIC_FIELDS, empty_observation


class RedisCollector:
    def __init__(self, host="127.0.0.1", port=6379, db=0, decode_responses=True):
        self.client = redis.Redis(host=host, port=port, db=db, decode_responses=decode_responses)

    @staticmethod
    def _to_int(value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_float(value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _risk_score(severity):
        return {
            "LOW": 0.25,
            "MEDIUM": 0.5,
            "HIGH": 0.75,
            "CRITICAL": 0.95,
        }.get(str(severity or "LOW").upper(), 0.25)

    def _load_agent_metrics(self, agent_id):
        raw = self.client.hgetall(f"inter:metric:{agent_id}")
        metrics = dict(AGENT_METRIC_FIELDS)
        metrics.update(
            {
                "cpu_usage": self._to_float(raw.get("cpu_usage")),
                "memory_usage": self._to_float(raw.get("memory_usage")),
                "api_call_count": self._to_int(raw.get("api_call_count")),
                "msg_sent": self._to_int(raw.get("msg_sent_count")),
                "msg_received": self._to_int(raw.get("msg_recv_count")),
                "proc_exec_count": self._to_int(raw.get("proc_exec_count")),
                "proc_fork_count": self._to_int(raw.get("proc_fork_count")),
                "fs_open_count": self._to_int(raw.get("fs_open_count")),
                "fs_read_count": self._to_int(raw.get("fs_read_count")),
                "fs_write_count": self._to_int(raw.get("fs_write_count")),
                "fs_unlink_count": self._to_int(raw.get("fs_unlink_count")),
                "net_connect_count": self._to_int(raw.get("net_connect_count")),
                "net_send_count": self._to_int(raw.get("net_send_count")),
                "net_recv_count": self._to_int(raw.get("net_recv_count")),
                "shell_exec_count": self._to_int(raw.get("shell_exec_count")),
                "sensitive_file_count": self._to_int(raw.get("sensitive_file_count")),
                "unique_files_count": self._to_int(raw.get("unique_files_count")),
                "workspace_violation": self._to_int(raw.get("workspace_violation")),
            }
        )
        return metrics, self._to_int(raw.get("window_start_ns")), self._to_int(raw.get("last_active_ns"))

    def _load_interactions(self):
        interactions = []
        for edge in sorted(self.client.smembers("inter:edges")):
            raw = self.client.hgetall(f"inter:edge:{edge}")
            if not raw:
                continue
            interactions.append(
                {
                    "src": raw.get("src", ""),
                    "dst": raw.get("dst", ""),
                    "type": raw.get("type", ""),
                    "weight": self._to_float(raw.get("weight"), 0.0),
                    "timestamp_ns": self._to_int(raw.get("last_seen_ns")),
                    "total_messages": self._to_int(raw.get("total_messages")),
                    "total_bytes": self._to_int(raw.get("total_bytes")),
                }
            )
        return interactions

    def _load_messages(self, limit):
        messages = []
        for _, fields in reversed(self.client.xrevrange("inter:messages", count=limit)):
            messages.append(
                {
                    "src": fields.get("src_agent", ""),
                    "dst": fields.get("dst_agent", ""),
                    "msg_type": fields.get("msg_type", ""),
                    "protocol": fields.get("protocol", ""),
                    "data_size": self._to_int(fields.get("data_size")),
                    "timestamp_ns": self._to_int(fields.get("timestamp_ns")),
                    "src_pid": self._to_int(fields.get("src_pid")),
                    "dst_pid": self._to_int(fields.get("dst_pid")),
                    "src_port": self._to_int(fields.get("src_port")),
                    "dst_port": self._to_int(fields.get("dst_port")),
                    "status_code": self._to_int(fields.get("status_code")),
                    "latency_us": self._to_int(fields.get("latency_us")),
                }
            )
        return messages

    def _load_anomalies(self, limit):
        anomalies = []
        for _, fields in reversed(self.client.xrevrange("inter:anomalies", count=limit)):
            severity = fields.get("severity", "LOW")
            anomalies.append(
                {
                    "agent_id": fields.get("agent_id", ""),
                    "rule": fields.get("rule", ""),
                    "severity": severity,
                    "risk_score": self._risk_score(severity),
                    "description": fields.get("reason", ""),
                    "timestamp_ns": self._to_int(fields.get("timestamp_ns")),
                    "pid": self._to_int(fields.get("pid")),
                    "comm": fields.get("comm", ""),
                    "object": fields.get("object", "-"),
                    "details": fields.get("details", "{}"),
                }
            )
        return anomalies

    def get_observation(self, message_limit=100, anomaly_limit=100):
        observation = empty_observation()
        window_start_ns = 0
        latest_ns = 0

        for agent_id in sorted(self.client.smembers("inter:agents")):
            metrics, agent_window_start, last_active = self._load_agent_metrics(agent_id)
            observation["agents"][agent_id] = metrics
            if agent_window_start and (window_start_ns == 0 or agent_window_start < window_start_ns):
                window_start_ns = agent_window_start
            if last_active > latest_ns:
                latest_ns = last_active

        observation["interactions"] = self._load_interactions()
        observation["messages"] = self._load_messages(message_limit)
        observation["anomalies"] = self._load_anomalies(anomaly_limit)
        observation["window_start_ns"] = window_start_ns
        observation["timestamp"] = latest_ns or time.time_ns()
        return observation
