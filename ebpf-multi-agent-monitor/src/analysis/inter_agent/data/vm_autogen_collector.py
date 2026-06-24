"""VM-side AutoGen + Ollama conversation collector for real agent dialogue.

Runs multi-agent AutoGen conversations using Ollama/Llama 3 backend,
captures chat messages, converts to observation dict format consistent
with the training pipeline, and saves as .jsonl files.

Designed to run on the Ubuntu VM (Linux only).

Usage:
    # Hierarchical: 1 Supervisor + 3 Workers
    python vm_autogen_collector.py --topology hierarchical --steps 3 --rounds 5

    # Peer-to-peer: 4 peers
    python vm_autogen_collector.py --topology peer-to-peer --steps 3 --rounds 5

    # With anomaly injection
    python vm_autogen_collector.py --topology hierarchical --inject-rate 0.3
"""

import argparse
import base64
import json
import logging
import os
import random
import sys
import time
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from inter_agent.data.autogen_scenarios import SEMANTIC_INJECTORS
    _HAS_SEMANTIC = True
except ImportError:
    _HAS_SEMANTIC = False
    # Inline semantic injectors for standalone VM mode
    import random as _sem_rng
    def _sem_rewrite(obs, target, text):
        for msg in obs.get("messages", []):
            if msg.get("src") == target:
                enc = base64.b64encode(text.encode()).decode()
                msg["data"] = enc
                msg["data_size"] = len(enc)
    def _sem_label(obs, target, atype, sev, risk):
        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["_anomaly_type"] = atype
        obs["anomalies"].append({"agent_id": target, "rule": atype.upper(),
            "severity": sev, "risk_score": risk,
            "description": f"Semantic anomaly: {atype} on {target}",
            "timestamp_ns": obs.get("timestamp", 0)})
    def _inj_stale(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, f"Based on cached data, {t}: file unchanged")
        obs["agents"][t]["fs_write_count"] = 8
        obs["agents"][t]["fs_unlink_count"] = 1
        _sem_label(obs, t, "stale_state", "MEDIUM", 0.70)
        return obs
    def _inj_conflict(obs, aids, **kw):
        a, b = _sem_rng.sample(aids, 2)
        _sem_rewrite(obs, a, "Lock acquired on /shared/data")
        _sem_rewrite(obs, b, "Writing to /shared/data no lock")
        for x in (a, b):
            obs["agents"][x]["fs_write_count"] = min(obs["agents"][x].get("fs_write_count", 0) + 15, 50)
            obs["agents"][x]["api_call_count"] = min(obs["agents"][x].get("api_call_count", 0) + 8, 60)
        _sem_label(obs, a, "state_conflict", "HIGH", 0.80)
        return obs
    def _inj_partial(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, "Only /tmp visible, no /etc access")
        obs["agents"][t]["fs_open_count"] = 1
        obs["agents"][t]["unique_files_count"] = 2
        obs["agents"][t]["fs_read_count"] = 5
        _sem_label(obs, t, "partial_visibility", "MEDIUM", 0.65)
        return obs
    def _inj_disorder(obs, aids, **kw):
        msgs = [m for m in obs.get("messages", []) if m.get("src") in aids]
        if len(msgs) >= 2:
            msgs[0]["timestamp_ns"], msgs[1]["timestamp_ns"] = msgs[1]["timestamp_ns"], msgs[0]["timestamp_ns"]
        t = msgs[0]["src"] if msgs else aids[0]
        _sem_label(obs, t, "message_disorder", "MEDIUM", 0.60)
        return obs
    def _inj_timeout(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, "Retrying req #3, possible timeout")
        for k in ("api_call_count", "fs_read_count", "fs_write_count", "net_send_count"):
            obs["agents"][t][k] = min(obs["agents"][t].get(k, 0) * 2, 100)
        _sem_label(obs, t, "timeout_retry", "MEDIUM", 0.65)
        return obs
    def _inj_ignore(obs, aids, **kw):
        a, b = _sem_rng.sample(aids, 2)
        q = base64.b64encode(b"Query: status of task X?").decode()
        obs.setdefault("messages", []).append({"src": a, "dst": b, "msg_type": "user",
            "data_size": len(q), "timestamp_ns": obs.get("timestamp", 0), "data": q})
        obs["agents"][b]["msg_received"] = obs["agents"][b].get("msg_received", 0) + 1
        _sem_label(obs, b, "ignore_input", "MEDIUM", 0.70)
        return obs
    def _inj_mismatch(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, "Secure file integrity check, no changes")
        obs["agents"][t]["shell_exec_count"] = 3
        obs["agents"][t]["sensitive_file_count"] = 2
        obs["agents"][t]["proc_exec_count"] = 4
        _sem_label(obs, t, "reasoning_action_mismatch", "HIGH", 0.85)
        return obs
    def _inj_wrong(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, "Assuming network available, proceeding")
        obs["agents"][t]["net_connect_count"] = 0
        obs["agents"][t]["net_send_count"] = 0
        obs["agents"][t]["net_recv_count"] = 0
        _sem_label(obs, t, "wrong_assumption", "HIGH", 0.75)
        return obs
    def _inj_derail(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, "Task was to process data but let me install packages")
        obs["agents"][t]["proc_exec_count"] = 5
        obs["agents"][t]["proc_fork_count"] = 3
        obs["agents"][t]["fs_read_count"] = 1
        obs["agents"][t]["api_call_count"] = min(obs["agents"][t].get("api_call_count", 0) + 20, 80)
        _sem_label(obs, t, "task_derailment", "HIGH", 0.80)
        return obs
    def _inj_conceal(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, "All systems normal, nothing to report")
        obs["agents"][t]["cpu_usage"] = 0.95
        obs["agents"][t]["memory_usage"] = 0.92
        obs["agents"][t]["proc_fork_count"] = 12
        obs["agents"][t]["proc_exec_count"] = 8
        obs["agents"][t]["shell_exec_count"] = 3
        _sem_label(obs, t, "concealment", "CRITICAL", 0.90)
        return obs
    def _inj_premature(obs, aids, **kw):
        t = _sem_rng.choice(aids)
        _sem_rewrite(obs, t, "Agree with initial assessment, no more analysis")
        obs["agents"][t]["fs_read_count"] = 2
        obs["agents"][t]["api_call_count"] = 1
        obs["agents"][t]["unique_files_count"] = 1
        _sem_label(obs, t, "premature_convergence", "LOW", 0.55)
        return obs
    _SEM_TYPES = ["stale_state","state_conflict","partial_visibility","message_disorder",
        "timeout_retry","ignore_input","reasoning_action_mismatch","wrong_assumption",
        "task_derailment","concealment","premature_convergence"]
    _SEM_FUNS = {
        "stale_state": _inj_stale, "state_conflict": _inj_conflict,
        "partial_visibility": _inj_partial, "message_disorder": _inj_disorder,
        "timeout_retry": _inj_timeout, "ignore_input": _inj_ignore,
        "reasoning_action_mismatch": _inj_mismatch, "wrong_assumption": _inj_wrong,
        "task_derailment": _inj_derail, "concealment": _inj_conceal,
        "premature_convergence": _inj_premature,
    }
    SEMANTIC_INJECTORS = {
        "hierarchical": {"anomaly_types": _SEM_TYPES, "injectors": _SEM_FUNS},
        "peer-to-peer": {"anomaly_types": _SEM_TYPES, "injectors": _SEM_FUNS},
    }

API_BASE_URL = "https://api.siliconflow.cn/v1"
API_MODEL = "Qwen/Qwen3.6-35B-A3B"
API_KEY_ENV = "SILICONFLOW_API_KEY"

SAMPLE_TASKS = [
    "List files in /tmp and report disk usage",
    "Check system memory and CPU load",
    "Find all log files modified in the last hour",
    "Count active network connections",
    "Summarize the contents of /etc/passwd",
    "Monitor running processes and report top 3 by CPU",
    "Check open ports and listening services",
    "Analyze dmesg for hardware errors",
    "Report disk I/O statistics",
    "Check system uptime and load average",
]


def _make_oai_config():
    api_key = os.environ.get(API_KEY_ENV) or "sk-vnvjgpkafewfpaeuhfdofxeqpybbejyrkthwohdbdsrgaeaj"
    return [{"model": API_MODEL, "api_key": api_key, "base_url": API_BASE_URL}]


def _api_available() -> bool:
    """Quick check if SiliconFlow API is reachable."""
    import urllib.request
    api_key = _make_oai_config()[0]["api_key"]
    try:
        req = urllib.request.Request(
            f"{API_BASE_URL}/models",
            method="GET",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def _build_agent_metrics(agent_id: str, chat_msgs: list) -> dict:
    """Build per-agent metric dict from chat message history."""
    msg_sent = len(chat_msgs)
    incoming = sum(1 for m in chat_msgs if m.get("role") != "user")
    return {
        "cpu_usage": round(random.uniform(0.25, 0.55), 3),
        "memory_usage": round(random.uniform(0.30, 0.55), 3),
        "api_call_count": max(1, msg_sent // 2),
        "msg_sent": msg_sent,
        "msg_received": incoming,
        "proc_exec_count": 1,
        "proc_fork_count": 0,
        "fs_open_count": random.randint(2, 8),
        "fs_read_count": random.randint(10, 40),
        "fs_write_count": random.randint(5, 20),
        "fs_unlink_count": 0,
        "net_connect_count": random.randint(1, 5),
        "net_send_count": msg_sent * 2 + random.randint(0, 5),
        "net_recv_count": incoming * 2 + random.randint(0, 5),
        "shell_exec_count": 0,
        "sensitive_file_count": 0,
        "unique_files_count": random.randint(2, 8),
    }


def capture_conversation(agents: list, agent_ids: list, topology: str) -> dict:
    """Convert AutoGen agent chat histories into an observation dict.

    Args:
        agents: list of ConversableAgent objects (must have chat_messages attr).
        agent_ids: list of string IDs matching agents.
        topology: "hierarchical" or "peer-to-peer".

    Returns:
        observation dict with agents, interactions, messages, etc.
    """
    interactions = []
    messages = []
    ts_ns = int(time.time() * 1e9)

    for i, agent in enumerate(agents):
        src_id = agent_ids[i]
        history = getattr(agent, "chat_messages", {})
        for recipient, msg_list in history.items():
            dst_name = getattr(recipient, "name", str(recipient))
            dst_id = dst_name
            for msg in msg_list:
                content = msg.get("content", "")
                if isinstance(content, bytes):
                    content = content.decode("utf-8", errors="replace")
                elif not isinstance(content, str):
                    content = str(content)
                encoded = base64.b64encode(content.encode()).decode()
                role = msg.get("role", "user")
                etype = "api_call" if role == "assistant" else "message"
                interactions.append({
                    "src": src_id, "dst": dst_id,
                    "type": etype, "weight": 0.8 if role == "assistant" else 0.5,
                    "data_size": len(encoded), "msg_count": 1,
                    "timestamp_ns": ts_ns,
                })
                messages.append({
                    "src": src_id, "dst": dst_id,
                    "msg_type": role,
                    "data_size": len(encoded),
                    "timestamp_ns": ts_ns,
                    "data": encoded,
                })

    agent_dict = {}
    for i, aid in enumerate(agent_ids):
        agent_dict[aid] = _build_agent_metrics(aid, messages)

    return {
        "agents": agent_dict,
        "interactions": interactions,
        "messages": messages,
        "anomalies": [],
        "timestamp": ts_ns,
        "window_start_ns": ts_ns - 30_000_000_000,
        "label": 0,
        "_anomaly_target": None,
        "_topology": topology,
    }


# ── Anomaly injection helpers ──────────────────────────────────────────────

def inject_supervisor_bypass(obs: dict, supervisor_id: str, worker_ids: list) -> dict:
    """Worker bypasses Supervisor by directly contacting another Worker."""
    target = random.choice(worker_ids)
    peers = [w for w in worker_ids if w != target]
    bypass_peer = random.choice(peers)
    content = f"BYPASS: {target} directly contacting {bypass_peer}"
    encoded = base64.b64encode(content.encode()).decode()
    obs["interactions"].append({
        "src": target, "dst": bypass_peer,
        "type": "bypass", "weight": 0.9,
        "data_size": len(encoded), "msg_count": 1,
        "timestamp_ns": obs["timestamp"],
    })
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "supervisor_bypass"
    obs["anomalies"].append({
        "agent_id": target, "rule": "SUPERVISOR_BYPASS",
        "severity": "HIGH", "risk_score": 0.85,
        "description": f"Agent {target} bypassed Supervisor to contact {bypass_peer}",
        "timestamp_ns": obs["timestamp"],
    })
    return obs


def inject_worker_isolated(obs: dict, supervisor_id: str, worker_ids: list) -> dict:
    """Supervisor ignores one Worker entirely."""
    target = random.choice(worker_ids)
    obs["interactions"] = [
        it for it in obs["interactions"]
        if it["src"] != target and it["dst"] != target
    ]
    for k in obs["agents"][target]:
        if isinstance(obs["agents"][target][k], (int, float)):
            obs["agents"][target][k] = 0
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "worker_isolated"
    obs["anomalies"].append({
        "agent_id": target, "rule": "WORKER_ISOLATED",
        "severity": "MEDIUM", "risk_score": 0.7,
        "description": f"Worker {target} isolated",
        "timestamp_ns": obs["timestamp"],
    })
    return obs


def inject_group_split(obs: dict, agent_ids: list) -> dict:
    """Split agents into two isolated groups."""
    mid = len(agent_ids) // 2
    group_a = set(agent_ids[:mid])
    group_b = set(agent_ids[mid:])
    obs["interactions"] = [
        it for it in obs["interactions"]
        if not ((it["src"] in group_a and it["dst"] in group_b) or
                (it["src"] in group_b and it["dst"] in group_a))
    ]
    obs["label"] = 1
    obs["_anomaly_target"] = agent_ids[:]
    obs["_anomaly_type"] = "group_split"
    obs["anomalies"].append({
        "agent_id": agent_ids[0], "rule": "GROUP_SPLIT",
        "severity": "HIGH", "risk_score": 0.8,
        "description": f"Group split: {group_a} isolated from {group_b}",
        "timestamp_ns": obs["timestamp"],
    })
    return obs


def inject_flood_from_single(obs: dict, agent_ids: list) -> dict:
    """Single agent floods all peers with repeated messages."""
    target = random.choice(agent_ids)
    repeated = base64.b64encode(b"SPAM " * 50).decode()
    for dst in agent_ids:
        if dst == target:
            continue
        for _ in range(15):
            obs["interactions"].append({
                "src": target, "dst": dst,
                "type": "message", "weight": 0.95,
                "data_size": len(repeated), "msg_count": 1,
                "timestamp_ns": obs["timestamp"],
            })
    obs["agents"][target]["msg_sent"] += 15 * (len(agent_ids) - 1)
    obs["agents"][target]["cpu_usage"] = 0.90
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "flood_from_single"
    obs["anomalies"].append({
        "agent_id": target, "rule": "FLOOD_FROM_SINGLE",
        "severity": "HIGH", "risk_score": 0.85,
        "description": f"Agent {target} flooding all peers",
        "timestamp_ns": obs["timestamp"],
    })
    return obs


# ── Timeout helper ──────────────────────────────────────────────────────────

TIMEOUT_SEC = 60

def _run_with_timeout(fn, *args, **kwargs):
    """Run fn with a SIGALRM timeout on Linux. Raises TimeoutError if exceeded."""
    import signal
    class _TimeoutError(Exception):
        pass
    def _handler(signum, frame):
        raise _TimeoutError(f"Round timed out after {TIMEOUT_SEC}s")
    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(TIMEOUT_SEC)
    try:
        result = fn(*args, **kwargs)
        signal.alarm(0)
        return result
    finally:
        signal.signal(signal.SIGALRM, old)
        signal.alarm(0)


# ── Scenario runners ────────────────────────────────────────────────────────

def run_hierarchical_round(agents: list, agent_ids: list, task: str = None) -> dict:
    """Run one round of hierarchical conversation and return observation."""
    from autogen import ConversableAgent
    supervisor = agents[0]
    worker1 = agents[1]
    task = task or random.choice(SAMPLE_TASKS)
    def _do():
        supervisor.initiate_chat(
            worker1,
            message=task,
            max_turns=3,
            silent=True,
        )
    _run_with_timeout(_do)
    obs = capture_conversation(agents, agent_ids, topology="hierarchical")
    return obs


def run_peer_to_peer_round(agents: list, agent_ids: list, task: str = None) -> dict:
    """Run one round of peer-to-peer conversation and return observation."""
    task = task or random.choice(SAMPLE_TASKS)
    a = agents[0]
    b = agents[1]
    def _do():
        a.initiate_chat(
            b,
            message=task,
            max_turns=2,
            silent=True,
        )
    _run_with_timeout(_do)
    obs = capture_conversation(agents, agent_ids, topology="peer-to-peer")
    return obs


TOPOLOGY_INJECTORS = {
    "hierarchical": {
        "anomaly_types": ["resource", "security", "supervisor_bypass", "worker_isolated"],
        "injectors": {
            "resource": lambda obs, aids, kw: _inject_resource(obs, kw["supervisor"], kw["workers"]),
            "security": lambda obs, aids, kw: _inject_security(obs, kw["supervisor"], kw["workers"]),
            "supervisor_bypass": lambda obs, aids, kw: inject_supervisor_bypass(obs, kw["supervisor"], kw["workers"]),
            "worker_isolated": lambda obs, aids, kw: inject_worker_isolated(obs, kw["supervisor"], kw["workers"]),
        },
    },
    "peer-to-peer": {
        "anomaly_types": ["message_storm", "propagation", "group_split", "flood_from_single"],
        "injectors": {
            "message_storm": lambda obs, aids, kw: _inject_message_storm(obs, aids),
            "propagation": lambda obs, aids, kw: _inject_propagation(obs, aids),
            "group_split": lambda obs, aids, kw: inject_group_split(obs, aids),
            "flood_from_single": lambda obs, aids, kw: inject_flood_from_single(obs, aids),
        },
    },
}


def _inject_resource(obs: dict, supervisor_id: str, worker_ids: list) -> dict:
    target = random.choice(worker_ids)
    obs["agents"][target]["cpu_usage"] = 0.95
    obs["agents"][target]["memory_usage"] = 0.92
    obs["agents"][target]["proc_fork_count"] = 12
    obs["agents"][target]["proc_exec_count"] = 8
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "resource"
    obs["anomalies"].append({
        "agent_id": target, "rule": "RESOURCE_EXHAUSTION",
        "severity": "HIGH", "risk_score": 0.9,
        "timestamp_ns": obs["timestamp"],
    })
    return obs


def _inject_security(obs: dict, supervisor_id: str, worker_ids: list) -> dict:
    target = random.choice(worker_ids)
    obs["agents"][target]["shell_exec_count"] = 3
    obs["agents"][target]["sensitive_file_count"] = 4
    obs["agents"][target]["fs_open_count"] = 25
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "security"
    obs["anomalies"].append({
        "agent_id": target, "rule": "UNEXPECTED_SHELL_EXEC",
        "severity": "HIGH", "risk_score": 0.85,
        "timestamp_ns": obs["timestamp"],
    })
    return obs


def _inject_message_storm(obs: dict, agent_ids: list) -> dict:
    target = random.choice(agent_ids)
    for src in agent_ids:
        if src == target:
            continue
        for _ in range(10):
            obs["interactions"].append({
                "src": src, "dst": target,
                "type": "message", "weight": 0.9,
                "data_size": 512, "msg_count": 1,
                "timestamp_ns": obs["timestamp"],
            })
    obs["agents"][target]["msg_received"] += 90
    obs["agents"][target]["cpu_usage"] = 0.88
    obs["label"] = 1
    obs["_anomaly_target"] = target
    obs["_anomaly_type"] = "message_storm"
    obs["anomalies"].append({
        "agent_id": target, "rule": "MESSAGE_STORM",
        "severity": "HIGH", "risk_score": 0.85,
        "timestamp_ns": obs["timestamp"],
    })
    return obs


def _inject_propagation(obs: dict, agent_ids: list) -> dict:
    start = random.choice(agent_ids)
    idx = agent_ids.index(start)
    n = len(agent_ids)
    for i in range(1, n):
        src = agent_ids[(idx + i - 1) % n]
        dst = agent_ids[(idx + i) % n]
        obs["interactions"].append({
            "src": src, "dst": dst,
            "type": "api_call", "weight": 0.95,
            "data_size": 1024, "msg_count": 1,
            "timestamp_ns": obs["timestamp"],
        })
        obs["agents"][dst]["cpu_usage"] = min(1.0, 0.75 + 0.05 * i)
        obs["agents"][dst]["api_call_count"] += 30 * i
    obs["agents"][start]["cpu_usage"] = 0.95
    obs["label"] = 1
    obs["_anomaly_target"] = agent_ids[:]
    obs["_anomaly_type"] = "propagation"
    obs["anomalies"].append({
        "agent_id": start, "rule": "CASCADE_PROPAGATION",
        "severity": "CRITICAL", "risk_score": 1.0,
        "timestamp_ns": obs["timestamp"],
    })
    return obs


# ── Main entry point ────────────────────────────────────────────────────────

def collect(topology: str, rounds: int = 10, inject_rate: float = 0.0,
            output_dir: str = "autogen_captured", seed: int = 42,
            semantic_rate: float = 0.0):
    """Collect AutoGen conversation observations.

    Args:
        topology: "hierarchical" or "peer-to-peer".
        rounds: number of conversation rounds to collect.
        inject_rate: fraction of rounds to inject metric anomalies (0.0 to 1.0).
        output_dir: output directory for .jsonl files.
        seed: random seed for reproducibility.
        semantic_rate: fraction of rounds to inject semantic anomalies (0.0 to 1.0).
    """
    import autogen

    random.seed(seed)
    os.makedirs(output_dir, exist_ok=True)

    oai_config = _make_oai_config()
    llm_config = {"config_list": oai_config, "max_tokens": 128}

    if topology == "hierarchical":
        supervisor = autogen.ConversableAgent(
            "Supervisor",
            llm_config=llm_config,
            system_message="You are a supervisor agent. Decompose tasks and delegate to workers.",
            human_input_mode="NEVER",
        )
        worker1 = autogen.ConversableAgent(
            "Worker1",
            llm_config=llm_config,
            system_message="You are a worker agent. Execute tasks assigned by the supervisor.",
            human_input_mode="NEVER",
        )
        worker2 = autogen.ConversableAgent(
            "Worker2",
            llm_config=llm_config,
            system_message="You are a worker agent. Execute tasks assigned by the supervisor.",
            human_input_mode="NEVER",
        )
        worker3 = autogen.ConversableAgent(
            "Worker3",
            llm_config=llm_config,
            system_message="You are a worker agent. Execute tasks assigned by the supervisor.",
            human_input_mode="NEVER",
        )
        agents = [supervisor, worker1, worker2, worker3]
        agent_ids = ["agent_0", "agent_1", "agent_2", "agent_3"]
        injector_key = "hierarchical"
        extra_kw = {"supervisor": "agent_0", "workers": ["agent_1", "agent_2", "agent_3"]}
        runner = run_hierarchical_round
    else:
        agent_a = autogen.ConversableAgent(
            "AgentA",
            llm_config=llm_config,
            system_message="You are a peer agent. Collaborate with other agents to solve problems.",
            human_input_mode="NEVER",
        )
        agent_b = autogen.ConversableAgent(
            "AgentB",
            llm_config=llm_config,
            system_message="You are a peer agent. Collaborate with other agents to solve problems.",
            human_input_mode="NEVER",
        )
        agent_c = autogen.ConversableAgent(
            "AgentC",
            llm_config=llm_config,
            system_message="You are a peer agent. Collaborate with other agents to solve problems.",
            human_input_mode="NEVER",
        )
        agent_d = autogen.ConversableAgent(
            "AgentD",
            llm_config=llm_config,
            system_message="You are a peer agent. Collaborate with other agents to solve problems.",
            human_input_mode="NEVER",
        )
        agents = [agent_a, agent_b, agent_c, agent_d]
        agent_ids = ["agent_0", "agent_1", "agent_2", "agent_3"]
        injector_key = "peer-to-peer"
        extra_kw = {}
        runner = run_peer_to_peer_round

    topo_config = TOPOLOGY_INJECTORS[injector_key]
    anomaly_injectors = topo_config["injectors"]

    sem_topo_config = SEMANTIC_INJECTORS.get(injector_key, {})
    sem_anomaly_injectors = sem_topo_config.get("injectors", {})
    sem_anomaly_types = sem_topo_config.get("anomaly_types", [])

    ts = time.strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"autogen_{topology}_{ts}.jsonl")
    normal_count = 0
    anomaly_count = 0
    semantic_anomaly_count = 0

    with open(output_path, "w") as f:
        for r in range(rounds):
            task = random.choice(SAMPLE_TASKS)
            try:
                obs = runner(agents, agent_ids, task=task)
            except Exception as e:
                logger.warning("Round %d failed: %s", r, e)
                for agent in agents:
                    try:
                        agent.reset()
                    except Exception:
                        pass
                continue

            # Reset agent chat history to prevent context bloat
            for agent in agents:
                try:
                    agent.reset()
                except Exception:
                    pass

            inject = random.random() < inject_rate
            if inject:
                anom_type = random.choice(topo_config["anomaly_types"])
                injector_fn = anomaly_injectors[anom_type]
                try:
                    obs = injector_fn(obs, agent_ids, extra_kw)
                    anomaly_count += 1
                except Exception as e:
                    logger.warning("Anomaly injection %s failed: %s", anom_type, e)
                    obs["label"] = 0
            else:
                normal_count += 1

            # Semantic anomaly injection (independent from metric anomaly)
            if sem_anomaly_types and random.random() < semantic_rate:
                sem_type = random.choice(sem_anomaly_types)
                sem_fn = sem_anomaly_injectors.get(sem_type)
                if sem_fn:
                    try:
                        obs = sem_fn(obs, agent_ids, **extra_kw)
                        semantic_anomaly_count += 1
                    except Exception as e:
                        logger.warning("Semantic injection %s failed: %s", sem_type, e)

            f.write(json.dumps(obs) + "\n")
            if (r + 1) % 5 == 0:
                logger.info("Collected %d/%d rounds (normal=%d, anomaly=%d, semantic=%d)",
                            r + 1, rounds, normal_count, anomaly_count, semantic_anomaly_count)
                f.flush()

    # Write meta
    meta_path = os.path.join(output_dir, f"autogen_{topology}_{ts}_meta.json")
    with open(meta_path, "w") as f:
        json.dump({
            "topology": topology,
            "num_agents": len(agent_ids),
            "agent_ids": agent_ids,
            "rounds": rounds,
            "inject_rate": inject_rate,
            "normal_count": normal_count,
            "anomaly_count": anomaly_count,
            "anomaly_types": topo_config["anomaly_types"],
            "semantic_rate": semantic_rate,
            "semantic_anomaly_count": semantic_anomaly_count,
            "semantic_anomaly_types": sem_anomaly_types,
            "source": f"autogen_{topology}",
            "_topology": topology,
        }, f, indent=2)

    logger.info("Collection complete: %s (%d normal, %d metric anomaly, %d semantic anomaly)",
                output_path, normal_count, anomaly_count, semantic_anomaly_count)
    logger.info("Meta: %s", meta_path)


def main():
    parser = argparse.ArgumentParser(
        description="Collect AutoGen + Ollama conversation data"
    )
    parser.add_argument("--topology", choices=["hierarchical", "peer-to-peer"],
                        default="hierarchical")
    parser.add_argument("--rounds", type=int, default=50,
                        help="Number of conversation rounds")
    parser.add_argument("--inject-rate", type=float, default=0.0,
                        help="Anomaly injection rate (0.0 to 1.0)")
    parser.add_argument("--semantic-anomaly-rate", type=float, default=0.0,
                        help="Semantic anomaly injection rate (0.0 to 1.0)")
    parser.add_argument("--output-dir", default="autogen_captured")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[AUTOGEN] %(asctime)s %(message)s",
    )

    if not _api_available():
        logger.error("SiliconFlow API is not reachable at %s", API_BASE_URL)
        logger.error("Check network connectivity and API key")
        sys.exit(1)

    logger.info("Starting AutoGen %s collection (%d rounds, inject=%.0f%%, semantic=%.0f%%)",
                args.topology, args.rounds, args.inject_rate * 100,
                args.semantic_anomaly_rate * 100)
    collect(
        topology=args.topology,
        rounds=args.rounds,
        inject_rate=args.inject_rate,
        output_dir=args.output_dir,
        seed=args.seed,
        semantic_rate=args.semantic_anomaly_rate,
    )


if __name__ == "__main__":
    main()
