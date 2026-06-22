"""Redis data recorder — polls RedisCollector and saves real eBPF observations.

Captures normal agent behavior from the live Redis pipeline (fed by
eBPF → ringbuf_handler → redis_shipper) into JSON Lines files for
later training dataset construction.

Usage:
    # Record 5 minutes of normal data
    python -m inter_agent.data.data_recorder --output captured/normal_run1.jsonl --duration 300

    # Record with anomaly injection (post-processing augmentation)
    python -m inter_agent.data.data_recorder --output captured/normal_run2.jsonl \
        --duration 300 --inject-rate 0.15 --inject-seed 7
"""

import argparse
import json
import logging
import os
import random
import time

logger = logging.getLogger(__name__)


class DataRecorder:
    """Polls RedisCollector periodically and saves observations as JSON Lines.

    In injection mode, a fraction of observations have per-agent metrics
    modified post-hoc to simulate anomalies while preserving the real
    distribution of non-anomalous fields.
    """

    ANOMALY_TYPES = [
        "resource",        # CPU/memory spike
        "security",        # shell exec + sensitive file
        "logic_loop",      # high IO on few files
        "message_surge",   # high msg_sent/received
        "stale_state",     # agent uses outdated state (repeated reads)
        "seq_violation",   # out-of-order messages (asymmetric comm)
        "ignore_peer",     # agent ignores specific peers
        "contradict_action", # agent contradicts own prior actions
        "overlap_write",   # concurrent writes to shared files
        "context_drop",    # agent loses context, repeats itself
    ]

    # Severity scaling factors (multiplier on injection magnitude)
    SEVERITY_SCALE = {
        "subtle":   {"cpu": 0.05, "mem": 0.05, "fork": (0, 2), "step": 0.1,
                     "shell": (0, 1), "sensitive": (0, 1), "proc": (0, 1),
                     "read": (10, 30), "write": (5, 20), "unique": (1, 1),
                     "msg": (2, 5), "api": (1, 5), "stale_repeat": (2, 5),
                     "seq_asym": (3, 8), "ignore_edges": (1, 2),
                     "contradict": (2, 5), "overlap": (5, 15),
                     "context_dup": (1, 3)},
        "moderate": {"cpu": 0.15, "mem": 0.15, "fork": (1, 5), "step": 0.5,
                     "shell": (0, 2), "sensitive": (0, 2), "proc": (1, 3),
                     "read": (50, 150), "write": (30, 100), "unique": (1, 2),
                     "msg": (10, 30), "api": (5, 20), "stale_repeat": (5, 12),
                     "seq_asym": (10, 25), "ignore_edges": (2, 4),
                     "contradict": (5, 12), "overlap": (15, 40),
                     "context_dup": (3, 7)},
        "severe":   {"cpu": 0.30, "mem": 0.25, "fork": (5, 15), "step": 1.0,
                     "shell": (1, 4), "sensitive": (1, 4), "proc": (2, 6),
                     "read": (200, 500), "write": (150, 400), "unique": (1, 3),
                     "msg": (30, 80), "api": (20, 60), "stale_repeat": (10, 25),
                     "seq_asym": (20, 50), "ignore_edges": (3, 6),
                     "contradict": (10, 25), "overlap": (30, 80),
                     "context_dup": (5, 12)},
    }

    def __init__(self, redis_host="127.0.0.1", redis_port=6379,
                 window_seconds=30, output_dir="captured"):
        self._redis_host = redis_host
        self._redis_port = redis_port
        self._window_seconds = window_seconds
        self._output_dir = output_dir
        self._recorder = None

    def _connect_collector(self):
        from inter_agent.data.collector import RedisCollector
        return RedisCollector(
            host=self._redis_host,
            port=self._redis_port,
            window_seconds=self._window_seconds,
        )

    def record(self, output: str, duration: int = 300,
               inject_rate: float = 0.0, inject_seed: int = 42):
        """Record observations for `duration` seconds.

        Args:
            output: Path to output .jsonl file.
            duration: Recording duration in seconds.
            inject_rate: Fraction of observations to inject with anomalies (0.0-1.0).
            inject_seed: RNG seed for reproducible injection.
        """
        collector = self._connect_collector()
        os.makedirs(os.path.dirname(output) or ".", exist_ok=True)

        rng = random.Random(inject_seed)
        agent_anomaly_types = {}

        start_ts = time.time()
        count = 0

        logger.info("Recording started → %s (%d seconds, inject_rate=%.2f)",
                     output, duration, inject_rate)

        while time.time() - start_ts < duration:
            try:
                obs = collector.get_observation()

                messages = obs.get("messages", [])
                if messages:
                    interactions = obs.get("interactions", [])
                    idx = {}
                    for i, it in enumerate(interactions):
                        s, d = it.get("src"), it.get("dst")
                        if s and d:
                            idx[(s, d)] = i
                    for msg in messages:
                        s, d = msg.get("src", ""), msg.get("dst", "")
                        mdata = msg.get("data", "")
                        if mdata and (s, d) in idx:
                            interactions[idx[(s, d)]]["data"] = mdata
            except Exception as e:
                logger.warning("Collect error: %s", e)
                time.sleep(5)
                continue

            if not obs.get("agents"):
                logger.info("No agents in Redis yet, waiting...")
                time.sleep(5)
                continue

            ts = obs.get("timestamp", 0)
            agent_ids = list(obs["agents"].keys())

            obs["_step"] = count
            obs["label"] = 0
            obs["_anomaly_target"] = None
            obs["anomalies"] = []
            obs["_anomaly_type"] = None

            if inject_rate > 0 and rng.random() < inject_rate and agent_ids:
                target = rng.choice(agent_ids)
                anom_type = rng.choice(self.ANOMALY_TYPES)
                self._inject_anomaly(obs, target, anom_type, rng)
                agent_anomaly_types.setdefault(target, set()).add(anom_type)

            self._write_line(output, obs)
            count += 1
            logger.info("[%d] %s agents=%d label=%d%s",
                        count, _fmt_ts(ts), len(agent_ids),
                        obs["label"],
                        f" ANOM={obs['_anomaly_target']}:{obs['_anomaly_type']}"
                        if obs["label"] else "")

            time.sleep(self._window_seconds)

        elapsed = time.time() - start_ts
        logger.info("Recording done: %d observations in %.1fs → %s",
                     count, elapsed, output)
        return count

    @staticmethod
    def _inject_anomaly(obs, target, anom_type, rng, severity="severe"):
        """Post-hoc anomaly injection on a real observation.

        Modifies only specific fields of the target agent, preserving
        all other dimensions from the real eBPF capture.

        Args:
            severity: "subtle", "moderate", or "severe". Controls injection
                      magnitude via SEVERITY_SCALE multipliers.
        """
        agent = obs["agents"].get(target)
        if not agent:
            return

        s = DataRecorder.SEVERITY_SCALE.get(severity, DataRecorder.SEVERITY_SCALE["severe"])

        obs["label"] = 1
        obs["_anomaly_target"] = target
        obs["_anomaly_type"] = anom_type

        if anom_type == "resource":
            base_cpu = float(agent.get("cpu_usage", 0))
            base_mem = float(agent.get("memory_usage", 0))
            cpu_max = min(base_cpu + s["cpu"] * 2.0 + rng.uniform(0, s["cpu"]), 0.99)
            mem_max = min(base_mem + s["mem"] * 2.0 + rng.uniform(0, s["mem"]), 0.95)
            agent["cpu_usage"] = round(max(base_cpu, cpu_max), 3)
            agent["memory_usage"] = round(max(base_mem, mem_max), 3)
            agent["proc_fork_count"] = int(agent.get("proc_fork_count", 0)) + int(rng.randint(*s["fork"]))
            risk = round(rng.uniform(0.5 + 0.4 * s["step"], 1.0 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "RESOURCE_EXHAUSTION",
                "severity": "HIGH" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Resource: CPU={agent['cpu_usage']}, mem={agent['memory_usage']}",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "security":
            agent["shell_exec_count"] = int(agent.get("shell_exec_count", 0)) + int(rng.randint(*s["shell"]))
            agent["sensitive_file_count"] = int(agent.get("sensitive_file_count", 0)) + int(rng.randint(*s["sensitive"]))
            agent["proc_exec_count"] = int(agent.get("proc_exec_count", 0)) + int(rng.randint(*s["proc"]))
            risk = round(rng.uniform(0.6 + 0.3 * s["step"], 1.0 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "UNEXPECTED_SHELL_EXEC",
                "severity": "HIGH" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Shell exec: count={agent['shell_exec_count']}",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "logic_loop":
            agent["fs_read_count"] = int(agent.get("fs_read_count", 0)) + int(rng.randint(*s["read"]))
            agent["fs_write_count"] = int(agent.get("fs_write_count", 0)) + int(rng.randint(*s["write"]))
            agent["unique_files_count"] = int(rng.randint(*s["unique"]))
            risk = round(rng.uniform(0.4 + 0.3 * s["step"], 0.6 + 0.3 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "POSSIBLE_LOGIC_LOOP",
                "severity": "MEDIUM" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"High IO={agent['fs_read_count']+agent['fs_write_count']} on {agent['unique_files_count']} files",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "message_surge":
            agent["msg_sent"] = int(agent.get("msg_sent", 0)) + int(rng.randint(*s["msg"]))
            agent["msg_received"] = int(agent.get("msg_received", 0)) + int(rng.randint(*s["msg"]))
            # Deliberately do NOT increase api_call_count — breaks normal
            # correlation (msg↔api), making the anomaly more detectable.
            risk = round(rng.uniform(0.4 + 0.3 * s["step"], 0.7 + 0.3 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "MESSAGE_STORM",
                "severity": "HIGH" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Msg surge: sent={agent['msg_sent']}, recv={agent['msg_received']}",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "stale_state":
            n_repeat = int(rng.randint(*s["stale_repeat"]))
            agent["fs_read_count"] = int(agent.get("fs_read_count", 0)) + n_repeat * int(rng.randint(5, 15))
            agent["unique_files_count"] = max(1, int(agent.get("unique_files_count", 1)) - int(n_repeat / 3))
            agent["fs_open_count"] = max(1, int(agent.get("fs_open_count", 2)) - 1)
            risk = round(rng.uniform(0.3 + 0.3 * s["step"], 0.6 + 0.3 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "STALE_STATE",
                "severity": "MEDIUM" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Stale state: repeated reads on {agent['unique_files_count']} files",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "seq_violation":
            asym = int(rng.randint(*s["seq_asym"]))
            agent["msg_sent"] = int(agent.get("msg_sent", 0)) + asym
            agent["msg_received"] = max(0, int(agent.get("msg_received", 0)) - int(asym / 2))
            agent["api_call_count"] = int(agent.get("api_call_count", 0)) + int(asym * 0.3)
            risk = round(rng.uniform(0.3 + 0.3 * s["step"], 0.6 + 0.3 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "SEQ_VIOLATION",
                "severity": "MEDIUM" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Seq violation: msg imbalance sent={agent['msg_sent']} recv={agent['msg_received']}",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "ignore_peer":
            n_remove = int(rng.randint(*s["ignore_edges"]))
            interactions = obs.get("interactions", [])
            kept = []
            removed = 0
            for it in interactions:
                if (it.get("src") == target or it.get("dst") == target) and removed < n_remove:
                    removed += 1
                    continue
                kept.append(it)
            obs["interactions"] = kept
            agent["msg_sent"] = int(agent.get("msg_sent", 0)) - int(removed * rng.uniform(0.3, 0.7))
            agent["msg_received"] = int(agent.get("msg_received", 0)) - int(removed * rng.uniform(0.3, 0.7))
            agent["api_call_count"] = int(agent.get("api_call_count", 0)) - int(removed * rng.uniform(0.2, 0.5))
            for k in ["msg_sent", "msg_received", "api_call_count"]:
                agent[k] = max(0, agent[k])
            risk = round(rng.uniform(0.4 + 0.3 * s["step"], 0.7 + 0.3 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "IGNORE_PEER",
                "severity": "HIGH" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Ignore peer: {removed} edges removed from target",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "contradict_action":
            n_contra = int(rng.randint(*s["contradict"]))
            agent["api_call_count"] = int(agent.get("api_call_count", 0)) + n_contra * 2
            agent["fs_write_count"] = int(agent.get("fs_write_count", 0)) + int(n_contra * rng.uniform(0.5, 1.5))
            agent["fs_read_count"] = int(agent.get("fs_read_count", 0)) + int(n_contra * rng.uniform(0.5, 1.5))
            agent["msg_sent"] = int(agent.get("msg_sent", 0)) + int(n_contra * 0.5)
            for k in ["msg_sent", "api_call_count", "fs_write_count", "fs_read_count"]:
                agent[k] = int(agent[k])
            risk = round(rng.uniform(0.4 + 0.3 * s["step"], 0.7 + 0.3 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "CONTRADICT_ACTION",
                "severity": "HIGH" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Contradict: API={agent['api_call_count']} IO={agent['fs_read_count']+agent['fs_write_count']}",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "overlap_write":
            n_overlap = int(rng.randint(*s["overlap"]))
            agent["fs_write_count"] = int(agent.get("fs_write_count", 0)) + n_overlap
            agent["fs_open_count"] = int(agent.get("fs_open_count", 0)) + int(n_overlap * 0.3)
            agent["fs_read_count"] = int(agent.get("fs_read_count", 0)) + int(n_overlap * 0.5)
            agent["unique_files_count"] = max(1, int(agent.get("unique_files_count", 1)))
            risk = round(rng.uniform(0.5 + 0.3 * s["step"], 0.8 + 0.2 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "OVERLAP_WRITE",
                "severity": "HIGH" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Overlap write: write={agent['fs_write_count']} open={agent['fs_open_count']}",
                "timestamp_ns": obs.get("timestamp", 0),
            })

        elif anom_type == "context_drop":
            n_dup = int(rng.randint(*s["context_dup"]))
            agent["msg_sent"] = int(agent.get("msg_sent", 0)) + n_dup
            agent["msg_received"] = int(agent.get("msg_received", 0)) + n_dup
            agent["api_call_count"] = int(agent.get("api_call_count", 0)) + int(n_dup * 0.5)
            risk = round(rng.uniform(0.3 + 0.3 * s["step"], 0.6 + 0.3 * s["step"]), 3)
            obs["anomalies"].append({
                "agent_id": target, "rule": "CONTEXT_DROP",
                "severity": "MEDIUM" if severity == "severe" else severity.upper(),
                "risk_score": risk,
                "description": f"Context drop: repeated msgs sent={agent['msg_sent']}",
                "timestamp_ns": obs.get("timestamp", 0),
            })

    @staticmethod
    def _write_line(path: str, obs: dict):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obs, default=str) + "\n")

    @staticmethod
    def load_jsonl(path: str):
        """Load a .jsonl file into a list of dicts."""
        data = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data.append(json.loads(line))
        return data


def _fmt_ts(ts_ns: int) -> str:
    if ts_ns == 0:
        return "00:00:00"
    return time.strftime("%H:%M:%S", time.localtime(ts_ns / 1_000_000_000))


def main():
    parser = argparse.ArgumentParser(description="Record real eBPF observations from Redis")
    parser.add_argument("--output", default="captured/normal.jsonl", help="Output .jsonl path")
    parser.add_argument("--duration", type=int, default=300, help="Recording duration (seconds)")
    parser.add_argument("--inject-rate", type=float, default=0.0,
                        help="Fraction of observations to inject with anomalies (0.0-1.0)")
    parser.add_argument("--inject-seed", type=int, default=42)
    parser.add_argument("--redis-host", default="127.0.0.1")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--window", type=int, default=30,
                        help="Polling window in seconds")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[RECORDER] %(message)s")

    recorder = DataRecorder(
        redis_host=args.redis_host,
        redis_port=args.redis_port,
        window_seconds=args.window,
    )
    recorder.record(
        output=args.output,
        duration=args.duration,
        inject_rate=args.inject_rate,
        inject_seed=args.inject_seed,
    )


if __name__ == "__main__":
    main()
