import json
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import redis as redis_mod
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis_mod = None


class BaseCollector:
    def get_observation(self):
        raise NotImplementedError


class RedisCollector(BaseCollector):
    """Collects inter-agent observation from Redis.

    Redis keys follow the schema defined in schema.py.
    Assumes intra_agent and event pipelines write to the same Redis instance.

    Required Redis keys:
        inter:agents               SET of agent IDs
        inter:metric:{agent_id}    HASH of per-agent counters
        inter:edges                SET of edge keys "src:dst"
        inter:edge:{src}:{dst}     HASH of edge attributes
        inter:messages             STREAM (optional) of messages
        inter:anomalies            STREAM (optional) of intra alerts
    """

    def __init__(self, host="127.0.0.1", port=6379, db=0,
                 password: Optional[str] = None,
                 window_seconds=30,
                 message_limit=100,
                 anomaly_limit=50):
        if not HAS_REDIS:
            raise ImportError(
                "redis package not installed. Install with: pip install redis"
            )
        self._client = redis_mod.Redis(
            host=host, port=port, db=db,
            password=password,
            decode_responses=True
        )
        self._window_seconds = window_seconds
        self._message_limit = message_limit
        self._anomaly_limit = anomaly_limit
        self._prev_agents = {}
        self._prev_prev_agents = {}
        self._check_connection()

    def _check_connection(self):
        try:
            self._client.ping()
            logger.info("Connected to Redis at %s:%d", self._client.connection_pool.connection_kwargs.get('host', '?'), self._client.connection_pool.connection_kwargs.get('port', 0))
        except Exception as e:
            logger.warning("Redis connection failed: %s", e)

    def _get_all_agent_ids(self):
        members = self._client.smembers("inter:agents")
        if not members:
            return ["agent_0", "agent_1", "agent_2", "agent_3"]
        return sorted(members)

    def _read_agent_metrics(self, agent_id):
        key = f"inter:metric:{agent_id}"
        data = self._client.hgetall(key)
        if not data:
            return {}
        result = {}
        int_fields = {
            "proc_exec_count", "proc_fork_count", "fs_open_count",
            "fs_read_count", "fs_write_count", "fs_unlink_count",
            "fs_rename_count", "fs_chmod_count", "fs_rmdir_count",
            "net_connect_count", "net_send_count", "net_recv_count",
            "net_bind_count", "net_listen_count",
            "api_call_count", "msg_sent_count", "msg_recv_count",
            "unique_files_count", "shell_exec_count",
            "sensitive_file_count", "workspace_violation",
            "window_start_ns", "last_active_ns",
            "ssl_msg_count", "ssl_total_bytes",
        }
        float_fields = {"cpu_usage", "memory_usage"}
        for k, v in data.items():
            k2 = k.replace("-", "_")
            if k2 in int_fields:
                try:
                    result[k2] = int(v)
                except (ValueError, TypeError):
                    result[k2] = 0
            elif k2 in float_fields:
                try:
                    result[k2] = float(v)
                except (ValueError, TypeError):
                    result[k2] = 0.0
            else:
                result[k2] = v
        return result

    def _read_ssl_metrics(self):
        """Read SSL edge data and return per-agent SSL counters."""
        ssl_metrics = {}
        for key in self._client.scan_iter(match="inter:edge:*:ssl"):
            parts = key.split(":")
            if len(parts) == 4 and parts[3] == "ssl":
                agent_id = parts[2]
                data = self._client.hgetall(key)
                if data:
                    ssl_metrics[agent_id] = {
                        "ssl_msg_count": int(data.get("total_messages", 0)),
                        "ssl_total_bytes": int(data.get("total_bytes", 0)),
                    }
        return ssl_metrics

    def _read_edges(self):
        edge_keys = self._client.smembers("inter:edges")
        interactions = []
        for ek in sorted(edge_keys):
            parts = ek.split(":", 1)
            if len(parts) != 2:
                continue
            src, dst = parts
            data = self._client.hgetall(f"inter:edge:{src}:{dst}")
            if not data:
                interactions.append({
                    "src": src, "dst": dst,
                    "type": "message", "weight": 0.5,
                    "timestamp_ns": 0
                })
            else:
                interactions.append({
                    "src": data.get("src", src),
                    "dst": data.get("dst", dst),
                    "type": data.get("type", "message"),
                    "weight": float(data.get("weight", 0.5)),
                    "data_size": int(data.get("total_bytes", 0)),
                    "msg_count": int(data.get("total_messages", 1)),
                    "timestamp_ns": int(data.get("last_seen_ns", 0)),
                })
        return interactions

    def _read_messages(self):
        try:
            raw = self._client.xrevrange(
                "inter:messages", count=self._message_limit
            )
        except Exception:
            logger.warning("Redis xrevrange inter:messages failed", exc_info=True)
            return []
        msgs = []
        for msg_id, fields in raw:
            entry = {k: v for k, v in fields.items()}
            msgs.append({
                "src": entry.get("src", ""),
                "dst": entry.get("dst", ""),
                "msg_type": entry.get("type", "request"),
                "data_size": int(entry.get("bytes", 0)),
                "timestamp_ns": int(entry.get("timestamp_ns", 0)),
                "protocol": entry.get("protocol", ""),
                "data": entry.get("data", ""),
                "content": entry.get("content", ""),
                "peer_agent": entry.get("peer_agent", ""),
            })
        return msgs

    def _read_anomalies(self):
        try:
            raw = self._client.xrevrange(
                "inter:anomalies", count=self._anomaly_limit
            )
        except Exception:
            logger.warning("Redis xrevrange inter:anomalies failed", exc_info=True)
            return []
        anomalies = []
        for anom_id, fields in raw:
            entry = {k: v for k, v in fields.items()}
            sev = entry.get("severity", "MEDIUM")
            sev_map = {"LOW": 0.3, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}
            anomalies.append({
                "agent_id": entry.get("agent_id", ""),
                "rule": entry.get("rule", ""),
                "severity": sev,
                "risk_score": sev_map.get(sev, 0.5),
                "description": entry.get("reason", ""),
                "timestamp_ns": int(entry.get("timestamp_ns", 0)),
            })
        return anomalies

    def get_observation(self):
        agent_ids = self._get_all_agent_ids()
        now_ns = time.time_ns()
        window_ns = now_ns - (self._window_seconds * 1_000_000_000)

        agents = {}
        ssl_metrics = self._read_ssl_metrics()
        for aid in agent_ids:
            metrics = self._read_agent_metrics(aid)
            ssl = ssl_metrics.get(aid, {})
            agents[aid] = {
                "cpu_usage": metrics.get("cpu_usage", 0.0),
                "memory_usage": metrics.get("memory_usage", 0.0),
                "api_call_count": metrics.get("api_call_count", 0),
                "msg_sent": metrics.get("msg_sent_count", 0),
                "msg_received": metrics.get("msg_recv_count", 0),
                "proc_exec_count": metrics.get("proc_exec_count", 0),
                "proc_fork_count": metrics.get("proc_fork_count", 0),
                "fs_open_count": metrics.get("fs_open_count", 0),
                "fs_read_count": metrics.get("fs_read_count", 0),
                "fs_write_count": metrics.get("fs_write_count", 0),
                "fs_unlink_count": metrics.get("fs_unlink_count", 0),
                "net_connect_count": metrics.get("net_connect_count", 0),
                "net_send_count": metrics.get("net_send_count", 0),
                "net_recv_count": metrics.get("net_recv_count", 0),
                "shell_exec_count": metrics.get("shell_exec_count", 0),
                "sensitive_file_count": metrics.get("sensitive_file_count", 0),
                "unique_files_count": metrics.get("unique_files_count", 0),
                "ssl_msg_count": ssl.get("ssl_msg_count", 0),
                "ssl_total_bytes": ssl.get("ssl_total_bytes", 0),
            }

        # ── temporal delta features ────────────────────────────────────
        DELTA_FIELDS = [
            "cpu_usage", "memory_usage", "api_call_count",
            "msg_sent", "msg_received", "proc_exec_count",
            "proc_fork_count", "fs_open_count", "fs_read_count",
            "fs_write_count", "fs_unlink_count", "net_connect_count",
            "net_send_count", "net_recv_count", "shell_exec_count",
            "sensitive_file_count", "unique_files_count",
            "ssl_msg_count", "ssl_total_bytes",
        ]
        for aid, adata in agents.items():
            prev = self._prev_agents.get(aid, {})
            for f in DELTA_FIELDS:
                cur_val = adata.get(f, 0)
                prev_val = prev.get(f, 0)
                if isinstance(cur_val, (int, float)):
                    adata[f + "_delta"] = cur_val - prev_val
            # acceleration (delta of delta)
            prev2 = self._prev_prev_agents.get(aid, {})
            for f in DELTA_FIELDS:
                d_key = f + "_delta"
                cur_d = adata.get(d_key, 0)
                prev_d = prev2.get(d_key, 0)
                if isinstance(cur_d, (int, float)):
                    adata[f + "_accel"] = cur_d - prev_d

        self._prev_prev_agents = self._prev_agents
        self._prev_agents = agents

        interactions = self._read_edges()
        messages = self._read_messages()
        anomalies = self._read_anomalies()

        return {
            "agents": agents,
            "interactions": interactions,
            "messages": messages,
            "anomalies": anomalies,
            "timestamp": now_ns,
            "window_start_ns": window_ns,
        }
