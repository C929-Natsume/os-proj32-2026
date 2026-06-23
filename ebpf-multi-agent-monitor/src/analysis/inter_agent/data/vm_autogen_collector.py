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
            output_dir: str = "autogen_captured", seed: int = 42):
    """Collect AutoGen conversation observations.

    Args:
        topology: "hierarchical" or "peer-to-peer".
        rounds: number of conversation rounds to collect.
        inject_rate: fraction of rounds to inject anomalies (0.0 to 1.0).
        output_dir: output directory for .jsonl files.
        seed: random seed for reproducibility.
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

    ts = time.strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"autogen_{topology}_{ts}.jsonl")
    normal_count = 0
    anomaly_count = 0

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

            f.write(json.dumps(obs) + "\n")
            if (r + 1) % 5 == 0:
                logger.info("Collected %d/%d rounds (normal=%d, anomaly=%d)",
                            r + 1, rounds, normal_count, anomaly_count)
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
            "source": f"autogen_{topology}",
            "_topology": topology,
        }, f, indent=2)

    logger.info("Collection complete: %s (%d normal, %d anomaly)",
                output_path, normal_count, anomaly_count)
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

    logger.info("Starting AutoGen %s collection (%d rounds, inject=%.0f%%)",
                args.topology, args.rounds, args.inject_rate * 100)
    collect(
        topology=args.topology,
        rounds=args.rounds,
        inject_rate=args.inject_rate,
        output_dir=args.output_dir,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
