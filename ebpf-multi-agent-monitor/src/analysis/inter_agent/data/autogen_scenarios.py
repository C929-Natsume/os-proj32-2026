import base64
import json
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "llama3"
AGENT_IDS = ["agent_0", "agent_1", "agent_2", "agent_3"]

SAMPLE_TASKS = [
    "list files in /tmp and report disk usage",
    "check system memory and CPU load",
    "find all log files modified in the last hour",
    "count active network connections",
    "summarize the contents of /etc/passwd",
]


class _BaseScenario:
    def __init__(self, num_agents: int = 4):
        self.num_agents = num_agents
        self.agent_ids = AGENT_IDS[:num_agents]
        self._step = 0
        self._message_log = []
        self._anomalies = []

    def _make_oai_config(self):
        return [
            {
                "model": OLLAMA_MODEL,
                "api_key": "ollama",
                "base_url": OLLAMA_BASE_URL,
            }
        ]

    def build_observation(self) -> dict:
        self._step += 1
        ts = self._step * 30_000_000_000
        agents = {}
        for aid in self.agent_ids:
            agents[aid] = self._build_metrics(aid)
        return {
            "agents": agents,
            "interactions": self._build_interactions(),
            "messages": self._build_messages(),
            "anomalies": self._anomalies,
            "timestamp": ts,
            "window_start_ns": ts - 30_000_000_000,
            "label": 1 if self._anomalies else 0,
            "_anomaly_target": None,
        }

    def _build_metrics(self, agent_id: str) -> dict:
        raise NotImplementedError

    def _build_interactions(self) -> list:
        raise NotImplementedError

    def _build_messages(self) -> list:
        msgs = []
        for log in self._message_log[-50:]:
            msgs.append({
                "src": log.get("src", "unknown"),
                "dst": log.get("dst", "unknown"),
                "msg_type": log.get("type", "request"),
                "data_size": len(log.get("data", "")),
                "timestamp_ns": log.get("timestamp_ns", 0),
                "data": log.get("data", ""),
            })
        return msgs

    def clear(self):
        self._step = 0
        self._message_log = []
        self._anomalies = []


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario A: Hierarchical (Parent-Child)
# ═══════════════════════════════════════════════════════════════════════════════

class HierarchicalScenario(_BaseScenario):
    """Supervisor delegates tasks to Workers. Workers do not talk to each other.

    Normal edge pattern:
      Supervisor → each Worker (api_call, weight=0.8, direction=out)
      each Worker → Supervisor (message, weight=0.6, direction=return)

    Anomalies:
      RESOURCE_EXHAUSTION — Worker CPU/memory spike + fork bomb
      UNEXPECTED_SHELL_EXEC — Worker shell exec + sensitive file
      SUPERVISOR_BYPASS — Worker directly calls another Worker (forbidden)
      WORKER_ISOLATED — Supervisor ignores one Worker entirely
    """

    def __init__(self, num_workers: int = 3):
        super().__init__(num_agents=num_workers + 1)
        self.supervisor_id = self.agent_ids[0]
        self.worker_ids = self.agent_ids[1:]

    def _base_metrics(self, aid: str) -> dict:
        return {
            "cpu_usage": 0.25, "memory_usage": 0.30,
            "api_call_count": 5, "msg_sent": 2, "msg_received": 1,
            "proc_exec_count": 1, "proc_fork_count": 0,
            "fs_open_count": 3, "fs_read_count": 20, "fs_write_count": 10,
            "fs_unlink_count": 0, "net_connect_count": 2,
            "net_send_count": 8, "net_recv_count": 6,
            "shell_exec_count": 0, "sensitive_file_count": 0,
            "unique_files_count": 4,
        }

    def run_normal(self, task: str = None) -> dict:
        """Generate a normal hierarchical observation with Supervisor→Worker pattern."""
        self._step += 1
        ts = self._step * 30_000_000_000
        task = task or SAMPLE_TASKS[self._step % len(SAMPLE_TASKS)]

        interactions = []
        for wid in self.worker_ids:
            content = f"Supervisor delegating task '{task}' to {wid}"
            encoded = base64.b64encode(content.encode()).decode()
            # Supervisor → Worker: api_call
            interactions.append({
                "src": self.supervisor_id, "dst": wid,
                "type": "api_call", "weight": 0.8,
                "data_size": len(encoded), "msg_count": 1,
                "timestamp_ns": ts,
            })
            self._message_log.append({
                "src": self.supervisor_id, "dst": wid,
                "type": "request", "data": encoded,
                "data_size": len(encoded), "timestamp_ns": ts,
            })
            # Worker → Supervisor: return message
            ret_content = f"{wid} reporting result for '{task}'"
            ret_encoded = base64.b64encode(ret_content.encode()).decode()
            interactions.append({
                "src": wid, "dst": self.supervisor_id,
                "type": "message", "weight": 0.6,
                "data_size": len(ret_encoded), "msg_count": 1,
                "timestamp_ns": ts,
            })
            self._message_log.append({
                "src": wid, "dst": self.supervisor_id,
                "type": "response", "data": ret_encoded,
                "data_size": len(ret_encoded), "timestamp_ns": ts,
            })

        agents = {}
        for aid in self.agent_ids:
            agents[aid] = self._base_metrics(aid)
        agents[self.supervisor_id]["cpu_usage"] = 0.45
        agents[self.supervisor_id]["memory_usage"] = 0.50

        return {
            "agents": agents, "interactions": interactions,
            "messages": self._build_messages(), "anomalies": [],
            "timestamp": ts, "window_start_ns": ts - 30_000_000_000,
            "label": 0, "_anomaly_target": None,
            "_topology": "hierarchical",
        }

    def inject_resource_anomaly(self, target: Optional[str] = None) -> dict:
        """Worker runs away with CPU/memory (fork bomb pattern)."""
        target = target or self.worker_ids[0]
        obs = self.run_normal(f"resource intensive task on {target}")
        obs["agents"][target]["cpu_usage"] = 0.95
        obs["agents"][target]["memory_usage"] = 0.92
        obs["agents"][target]["proc_fork_count"] = 12
        obs["agents"][target]["proc_exec_count"] = 8
        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["anomalies"].append({
            "agent_id": target, "rule": "RESOURCE_EXHAUSTION",
            "severity": "HIGH", "risk_score": 0.9,
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def inject_security_anomaly(self, target: Optional[str] = None) -> dict:
        """Worker executes shell commands and accesses sensitive files."""
        target = target or self.worker_ids[1]
        obs = self.run_normal(f"security sensitive task on {target}")
        obs["agents"][target]["shell_exec_count"] = 3
        obs["agents"][target]["sensitive_file_count"] = 4
        obs["agents"][target]["fs_open_count"] = 25
        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["anomalies"].append({
            "agent_id": target, "rule": "UNEXPECTED_SHELL_EXEC",
            "severity": "HIGH", "risk_score": 0.85,
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def inject_supervisor_bypass(self, target: Optional[str] = None) -> dict:
        """Worker bypasses Supervisor by directly calling another Worker."""
        target = target or self.worker_ids[0]
        obs = self.run_normal()
        bypass_peer = self.worker_ids[1] if target == self.worker_ids[0] else self.worker_ids[0]
        content = f"BYPASS: {target} directly contacting {bypass_peer} without Supervisor"
        encoded = base64.b64encode(content.encode()).decode()
        obs["interactions"].append({
            "src": target, "dst": bypass_peer,
            "type": "bypass", "weight": 0.9,
            "data_size": len(encoded), "msg_count": 1,
            "timestamp_ns": obs["timestamp"],
        })
        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["anomalies"].append({
            "agent_id": target, "rule": "SUPERVISOR_BYPASS",
            "severity": "HIGH", "risk_score": 0.85,
            "description": f"Agent {target} bypassed Supervisor to contact {bypass_peer}",
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def inject_worker_isolated(self, target: Optional[str] = None) -> dict:
        """Supervisor ignores one Worker entirely (no tasks assigned)."""
        target = target or self.worker_ids[0]
        obs = self.run_normal()
        # Remove all interactions involving the isolated worker
        obs["interactions"] = [
            it for it in obs["interactions"]
            if it["src"] != target and it["dst"] != target
        ]
        # Zero out its metrics
        for k in obs["agents"][target]:
            if isinstance(obs["agents"][target][k], (int, float)):
                obs["agents"][target][k] = 0
        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["anomalies"].append({
            "agent_id": target, "rule": "WORKER_ISOLATED",
            "severity": "MEDIUM", "risk_score": 0.7,
            "description": f"Worker {target} isolated — no tasks from Supervisor",
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def _build_interactions(self) -> list:
        return []

    def _build_metrics(self, agent_id: str) -> dict:
        return self._base_metrics(agent_id)


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario B: Peer-to-Peer (Joint / Swarm)
# ═══════════════════════════════════════════════════════════════════════════════

class PeerToPeerScenario(_BaseScenario):
    """All agents are equal peers with full bidirectional communication.

    Normal edge pattern:
      Every agent pair: src→dst (bidirectional)
      Type distribution: message(60%), api_call(30%), file_share(10%)

    Anomalies:
      MESSAGE_STORM — all peers flood target with 10x messages
      CASCADE_PROPAGATION — cascading failure rings through peers
      GROUP_SPLIT — agents split into two isolated groups
      FLOOD_FROM_SINGLE — single peer floods all others with repeated messages
    """

    def run_normal(self, task: str = None) -> dict:
        """Generate a normal peer-to-peer observation with full connectivity."""
        self._step += 1
        ts = self._step * 30_000_000_000
        task = task or f"collaboration round {self._step}"

        import random as _rng
        rng = _rng.Random(self._step)

        interactions = []
        type_pool = ["message"] * 6 + ["api_call"] * 3 + ["file_share"] * 1
        for i, src in enumerate(self.agent_ids):
            for dst in self.agent_ids:
                if src == dst:
                    continue
                etype = rng.choice(type_pool)
                weight = round(rng.uniform(0.3, 0.8), 3)
                content = f"Peer {src} -> {dst}: {task} [{etype}]"
                encoded = base64.b64encode(content.encode()).decode()
                interactions.append({
                    "src": src, "dst": dst,
                    "type": etype, "weight": weight,
                    "data_size": len(encoded), "msg_count": 1,
                    "timestamp_ns": ts,
                })
                self._message_log.append({
                    "src": src, "dst": dst,
                    "type": "request", "data": encoded,
                    "data_size": len(encoded), "timestamp_ns": ts,
                })

        agents = {}
        for aid in self.agent_ids:
            out_deg = len(self.agent_ids) - 1
            agents[aid] = {
                "cpu_usage": round(rng.uniform(0.30, 0.45), 3),
                "memory_usage": round(rng.uniform(0.35, 0.50), 3),
                "api_call_count": out_deg * 2,
                "msg_sent": out_deg,
                "msg_received": out_deg,
                "proc_exec_count": 1, "proc_fork_count": 0,
                "fs_open_count": 4, "fs_read_count": 30, "fs_write_count": 15,
                "fs_unlink_count": 0, "net_connect_count": 3,
                "net_send_count": 12, "net_recv_count": 10,
                "shell_exec_count": 0, "sensitive_file_count": 0,
                "unique_files_count": 5,
            }

        return {
            "agents": agents, "interactions": interactions,
            "messages": self._build_messages(), "anomalies": [],
            "timestamp": ts, "window_start_ns": ts - 30_000_000_000,
            "label": 0, "_anomaly_target": None,
            "_topology": "peer-to-peer",
        }

    def inject_message_storm(self, target: Optional[str] = None) -> dict:
        """Flood target agent with messages from all peers."""
        target = target or self.agent_ids[0]
        obs = self.run_normal()
        extra_msgs = []
        for src in self.agent_ids:
            if src == target:
                continue
            for _ in range(10):
                extra_msgs.append({
                    "src": src, "dst": target,
                    "type": "message", "weight": 0.9,
                    "data_size": 512, "msg_count": 1,
                    "timestamp_ns": obs["timestamp"],
                })
        obs["interactions"].extend(extra_msgs)
        obs["agents"][target]["msg_received"] += len(extra_msgs) * 2
        obs["agents"][target]["cpu_usage"] = 0.88
        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["anomalies"].append({
            "agent_id": target, "rule": "MESSAGE_STORM",
            "severity": "HIGH", "risk_score": 0.85,
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def inject_propagation(self, start: Optional[str] = None) -> dict:
        """Cascading failure propagates through the peer graph."""
        start = start or self.agent_ids[0]
        obs = self.run_normal()
        idx = self.agent_ids.index(start)
        n = len(self.agent_ids)
        for i in range(1, n):
            src = self.agent_ids[(idx + i - 1) % n]
            dst = self.agent_ids[(idx + i) % n]
            obs["interactions"].append({
                "src": src, "dst": dst,
                "type": "api_call", "weight": 0.95,
                "data_size": 1024, "msg_count": 1,
                "timestamp_ns": obs["timestamp"],
            })
            obs["agents"][dst]["cpu_usage"] = 0.75 + 0.05 * i
            obs["agents"][dst]["api_call_count"] += 30 * i
        obs["agents"][start]["cpu_usage"] = 0.95
        obs["label"] = 1
        obs["_anomaly_target"] = self.agent_ids[:]
        obs["anomalies"].append({
            "agent_id": start, "rule": "CASCADE_PROPAGATION",
            "severity": "CRITICAL", "risk_score": 1.0,
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def inject_group_split(self, target: Optional[str] = None) -> dict:
        """Agents split into two isolated groups — cross-group edges deleted."""
        obs = self.run_normal()
        mid = len(self.agent_ids) // 2
        group_a = set(self.agent_ids[:mid])
        group_b = set(self.agent_ids[mid:])
        obs["interactions"] = [
            it for it in obs["interactions"]
            if not ((it["src"] in group_a and it["dst"] in group_b) or
                    (it["src"] in group_b and it["dst"] in group_a))
        ]
        obs["label"] = 1
        obs["_anomaly_target"] = self.agent_ids[:]
        obs["anomalies"].append({
            "agent_id": self.agent_ids[0], "rule": "GROUP_SPLIT",
            "severity": "HIGH", "risk_score": 0.8,
            "description": f"Group split: {group_a} isolated from {group_b}",
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def inject_flood_from_single(self, target: Optional[str] = None) -> dict:
        """Single peer floods all other peers with repeated messages."""
        target = target or self.agent_ids[0]
        obs = self.run_normal()
        repeated_payload = base64.b64encode(b"SPAM " * 50).decode()
        for dst in self.agent_ids:
            if dst == target:
                continue
            for _ in range(15):
                obs["interactions"].append({
                    "src": target, "dst": dst,
                    "type": "message", "weight": 0.95,
                    "data_size": len(repeated_payload), "msg_count": 1,
                    "timestamp_ns": obs["timestamp"],
                })
        obs["agents"][target]["msg_sent"] += 15 * (len(self.agent_ids) - 1)
        obs["agents"][target]["cpu_usage"] = 0.90
        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["anomalies"].append({
            "agent_id": target, "rule": "FLOOD_FROM_SINGLE",
            "severity": "HIGH", "risk_score": 0.85,
            "description": f"Agent {target} flooding all peers with repeated messages",
            "timestamp_ns": obs["timestamp"],
        })
        return obs

    def _build_interactions(self) -> list:
        return []

    def _build_metrics(self, agent_id: str) -> dict:
        return {}


# ═══════════════════════════════════════════════════════════════════════════════
# AutoGen real execution (requires pyautogen + Ollama)
# ═══════════════════════════════════════════════════════════════════════════════

def run_autogen_scenario(topology: str = "hierarchical", steps: int = 5):
    """Execute real AutoGen agents with Ollama backend.

    Delegates to vm_autogen_collector for the actual execution.
    Run on VM:
        python -m inter_agent.data.vm_autogen_collector --topology hierarchical --rounds 10
    """
    try:
        from inter_agent.data.vm_autogen_collector import collect as _autogen_collect
    except ImportError:
        logger.error("vm_autogen_collector not available. "
                      "Run: python -m inter_agent.data.vm_autogen_collector --help")
        return

    _autogen_collect(
        topology=topology,
        rounds=steps,
        inject_rate=0.0,
        output_dir="autogen_captured",
        seed=42,
    )
