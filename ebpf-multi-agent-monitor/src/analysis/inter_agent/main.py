"""Multi-agent collaborative anomaly detection entry point.

Usage:
    python -m inter_agent.main                  # run interactive loop
    python -m inter_agent.main --once           # single-shot detection
    python -m inter_agent.main --simulate       # run with simulated data
"""

import argparse
import base64
import json
import logging
import os
import sys
import time
from collections import defaultdict, deque

logging.basicConfig(level=logging.INFO, format="[INTER] %(message)s")
logger = logging.getLogger("inter_agent")


EVENT_EXECVE = 1
EVENT_FORK = 2
EVENT_OPEN = 3
EVENT_UNLINK = 4
EVENT_CONNECT = 5
EVENT_SSL_READ = 6
EVENT_SSL_WRITE = 7
EVENT_STDIO_READ = 10
EVENT_STDIO_WRITE = 11
EVENT_TCP_SEND = 12
EVENT_TCP_RECV = 13


class InterAgentAnalyzer:
    """Adapter used by main_analyzer.py for real-time inter-agent detection.

    The original inter_agent package exposes MonitorAgent over full observations.
    main_analyzer pushes one eBPF event at a time, so this adapter keeps a
    rolling observation and converts each incoming event into the schema
    expected by MonitorAgent.
    """

    def __init__(self, window_seconds=30):
        from inter_agent.monitor.agent import MonitorAgent
        from inter_agent.config import load_config

        base_dir = os.path.dirname(os.path.abspath(__file__))
        config = load_config()
        config["llm"] = {"enabled": False}
        config.setdefault("detection", {})
        config["detection"]["anomaly_threshold"] = float(
            config["detection"].get("anomaly_threshold", 0.3)
        )
        config["log"] = {
            "output_dir": os.path.abspath(
                os.path.join(base_dir, "..", "..", "..", "logs", "inter_log")
            )
        }
        model_path = os.path.join(base_dir, "models", "anomaly_detector.pth")
        self.agent = MonitorAgent(
            config=config,
            model_path=model_path if os.path.exists(model_path) else None,
        )
        self.window_ns = int(window_seconds * 1_000_000_000)
        self.metrics = defaultdict(self._new_metrics)
        self.messages = deque(maxlen=120)
        self.interactions = deque(maxlen=120)
        self.last_alert_ns = {}
        self.alert_cooldown_ns = 5 * 1_000_000_000
        logger.info("InterAgentAnalyzer adapter ready; output=%s", config["log"]["output_dir"])

    @staticmethod
    def _new_metrics():
        return {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "api_call_count": 0,
            "msg_sent": 0,
            "msg_received": 0,
            "proc_exec_count": 0,
            "proc_fork_count": 0,
            "fs_open_count": 0,
            "fs_read_count": 0,
            "fs_write_count": 0,
            "fs_unlink_count": 0,
            "net_connect_count": 0,
            "net_send_count": 0,
            "net_recv_count": 0,
            "shell_exec_count": 0,
            "sensitive_file_count": 0,
            "unique_files_count": 0,
            "ssl_msg_count": 0,
            "ssl_total_bytes": 0,
            "_files": set(),
            "_ebpf_pid": 0,
        }

    @staticmethod
    def _agent_id(event_data):
        aid = event_data.get("agent_id")
        if aid:
            return str(aid)
        return f"agent_{int(event_data.get('pid', 0) or 0)}"

    @staticmethod
    def _is_sensitive(path):
        text = str(path or "")
        return any(token in text for token in ("/etc/passwd", "/.ssh/", ".env", "/etc/shadow"))

    @staticmethod
    def _is_shell(path):
        base = os.path.basename(str(path or ""))
        return base in {"bash", "sh", "zsh", "fish", "dash"}

    @staticmethod
    def _message_payload(text):
        raw = str(text or "").encode("utf-8", errors="replace")
        return base64.b64encode(raw).decode("ascii")

    def _trim_window(self, now_ns):
        cutoff = now_ns - self.window_ns
        while self.messages and int(self.messages[0].get("timestamp_ns", 0)) < cutoff:
            self.messages.popleft()
        while self.interactions and int(self.interactions[0].get("timestamp_ns", 0)) < cutoff:
            self.interactions.popleft()

    def _update_from_event(self, event_data):
        event_type = int(event_data.get("type", 0) or 0)
        ts_ns = int(event_data.get("timestamp", time.time_ns()) or time.time_ns())
        aid = self._agent_id(event_data)
        metrics = self.metrics[aid]
        metrics["_ebpf_pid"] = int(event_data.get("pid", 0) or 0)

        obj = event_data.get("filename") or event_data.get("dip") or event_data.get("object") or ""
        data = str(event_data.get("data", "") or "")
        data_len = int(event_data.get("data_len", len(data.encode("utf-8", errors="ignore"))) or 0)

        if event_type == EVENT_EXECVE:
            metrics["proc_exec_count"] += 1
            metrics["api_call_count"] += 1
            if self._is_shell(obj):
                metrics["shell_exec_count"] += 1
        elif event_type == EVENT_FORK:
            metrics["proc_fork_count"] += 1
        elif event_type == EVENT_OPEN:
            metrics["fs_open_count"] += 1
            metrics["fs_read_count"] += 1
            if obj:
                metrics["_files"].add(str(obj))
                metrics["unique_files_count"] = len(metrics["_files"])
            if self._is_sensitive(obj):
                metrics["sensitive_file_count"] += 1
        elif event_type == EVENT_UNLINK:
            metrics["fs_unlink_count"] += 1
            if obj:
                metrics["_files"].add(str(obj))
                metrics["unique_files_count"] = len(metrics["_files"])
            if self._is_sensitive(obj):
                metrics["sensitive_file_count"] += 1
        elif event_type == EVENT_CONNECT:
            metrics["net_connect_count"] += 1
            dst = f"{event_data.get('dip', 'external')}:{event_data.get('dport', '')}".rstrip(":")
            self.interactions.append({
                "src": aid,
                "dst": dst or "external",
                "type": "network",
                "weight": 0.6,
                "data_size": 0,
                "msg_count": 1,
                "timestamp_ns": ts_ns,
            })
        elif event_type in (EVENT_SSL_WRITE, EVENT_STDIO_WRITE, EVENT_TCP_SEND):
            metrics["msg_sent"] += 1
            metrics["net_send_count"] += 1 if event_type == EVENT_TCP_SEND else 0
            metrics["ssl_msg_count"] += 1 if event_type == EVENT_SSL_WRITE else 0
            metrics["ssl_total_bytes"] += data_len if event_type == EVENT_SSL_WRITE else 0
            dst = str(event_data.get("peer_agent") or event_data.get("dst") or "external")
            self.messages.append({
                "src": aid,
                "dst": dst,
                "msg_type": "send",
                "data_size": data_len,
                "timestamp_ns": ts_ns,
                "protocol": event_data.get("_protocol") or event_data.get("protocol") or "runtime",
                "data": self._message_payload(data),
            })
            self.interactions.append({
                "src": aid,
                "dst": dst,
                "type": "message",
                "weight": min(1.0, max(0.1, data_len / 4096)),
                "data_size": data_len,
                "msg_count": 1,
                "timestamp_ns": ts_ns,
            })
        elif event_type in (EVENT_SSL_READ, EVENT_STDIO_READ, EVENT_TCP_RECV):
            metrics["msg_received"] += 1
            metrics["net_recv_count"] += 1 if event_type == EVENT_TCP_RECV else 0
            metrics["ssl_msg_count"] += 1 if event_type == EVENT_SSL_READ else 0
            metrics["ssl_total_bytes"] += data_len if event_type == EVENT_SSL_READ else 0
            src = str(event_data.get("peer_agent") or event_data.get("src") or "external")
            self.messages.append({
                "src": src,
                "dst": aid,
                "msg_type": "recv",
                "data_size": data_len,
                "timestamp_ns": ts_ns,
                "protocol": event_data.get("_protocol") or event_data.get("protocol") or "runtime",
                "data": self._message_payload(data),
            })

        self._trim_window(ts_ns)
        return aid, ts_ns

    def _observation(self, now_ns):
        agents = {}
        for aid, values in self.metrics.items():
            agents[aid] = {
                key: value
                for key, value in values.items()
                if key != "_files"
            }
        return {
            "agents": agents,
            "interactions": list(self.interactions),
            "messages": list(self.messages),
            "anomalies": [],
            "timestamp": now_ns,
            "window_start_ns": now_ns - self.window_ns,
        }

    def _primary_anomaly_type(self, report, obs):
        sem = getattr(report, "semantic_result", {}) or {}
        anomaly_types = sem.get("anomaly_types", []) or []
        if anomaly_types:
            return str(anomaly_types[0])
        obs_type = str(obs.get("_anomaly_type", "") or "").strip()
        if obs_type and obs_type != "normal":
            return obs_type
        return "inter_agent_anomaly"

    def _classify_module(self, anomaly_type):
        try:
            return str(self.agent._classify_module(anomaly_type))
        except Exception:
            return "unknown"

    def _semantic_lines(self, obs, anomaly_type, aid):
        try:
            ctx = self.agent._build_semantic_context(obs, anomaly_type, aid) or {}
        except Exception:
            ctx = {}
        if not ctx:
            return []
        lines = []
        sender = str(ctx.get("sender", "") or "").strip()
        receiver = str(ctx.get("receiver", "") or "").strip()
        content = str(ctx.get("content", "") or "").strip()
        if sender or receiver:
            lines.append(f"sender: {sender or '?'} -> receiver: {receiver or '?'}")
        if content:
            lines.append(f'content: "{content[:160]}"')
        return lines

    def _event_lines(self, obs, aid):
        try:
            events = self.agent._collect_events(obs, [aid], num=6)
        except Exception:
            events = []
        lines = []
        for event in events:
            detail = str(event.get("detail", "") or "").strip()
            agent = str(event.get("agent", aid) or aid)
            op = str(event.get("op", "unknown") or "unknown")
            target = str(event.get("target", "?") or "?")
            if detail:
                detail = detail[:120]
                lines.append(f'{agent}  {op} -> {target}  "{detail}"')
            else:
                lines.append(f"{agent}  {op} -> {target}")
        return lines

    def _view_lines(self, obs, anomaly_type):
        try:
            view = self.agent._analyze_view(obs, anomaly_type) or {}
        except Exception:
            view = {}
        lines = []
        topology = str(view.get("topology", "unknown") or "unknown")
        agents = int(view.get("agents", 0) or 0)
        edges = int(view.get("edges", 0) or 0)
        lines.append(f"topology={topology}  agents={agents}  edges={edges}")
        agent_list = str(view.get("agent_list", "") or "").strip()
        if agent_list:
            lines.append(f"agents: {agent_list}")
        return lines

    def _root_cause(self, report, obs, aid, anomaly_type):
        evidence = {}
        try:
            evidence = self.agent._semantic_rule_checker.get_evidence(obs) or {}
        except Exception:
            evidence = {}
        try:
            ev = evidence.get(aid, {}).get(anomaly_type, {})
            if ev:
                return str(self.agent._semantic_rule_checker.get_root_cause(anomaly_type, ev))
        except Exception:
            pass
        return f"Anomaly type '{anomaly_type}' detected on {aid}"

    def _analysis_report(self, report, anomaly_type, aid):
        response = getattr(report, "response_level", None)
        response_text = response.value if response else "PASS"
        risk = max(
            float(getattr(report, "max_risk", 0) or 0),
            float(getattr(report, "rule_risks", {}).get(aid, 0) or 0),
            float(getattr(report, "temporal_risks", {}).get(aid, 0) or 0),
            float(getattr(report, "gnn_risks", {}).get(aid, 0) or 0),
        )
        source = str(getattr(report, "source_agent", "") or "").strip()
        node_count = len(getattr(report, "anomalous_nodes", []) or [])
        parts = [
            f"type={anomaly_type}",
            f"response={response_text}",
            f"risk={risk:.3f}",
            f"anomalous_agents={node_count}",
        ]
        if source:
            parts.append(f"source_agent={source}")
        return " | ".join(parts)

    def _report_to_alerts(self, report, obs, event_data, now_ns):
        alerts = []
        for aid in report.anomalous_nodes:
            last = self.last_alert_ns.get(aid, 0)
            if now_ns - last < self.alert_cooldown_ns:
                continue
            self.last_alert_ns[aid] = now_ns
            risk = max(
                float(report.max_risk or 0),
                float(report.rule_risks.get(aid, 0) or 0),
                float(report.temporal_risks.get(aid, 0) or 0),
                float(report.gnn_risks.get(aid, 0) or 0),
            )
            anomaly_type = self._primary_anomaly_type(report, obs)
            module = self._classify_module(anomaly_type)
            event_lines = self._event_lines(obs, aid)
            semantic_lines = self._semantic_lines(obs, anomaly_type, aid)
            view_lines = self._view_lines(obs, anomaly_type)
            root_cause = self._root_cause(report, obs, aid, anomaly_type)
            analysis_report = self._analysis_report(report, anomaly_type, aid)
            source_agent = str(getattr(report, "source_agent", "") or "")
            anomalous_agents = [str(x) for x in list(getattr(report, "anomalous_nodes", []) or [])]
            propagation_paths = list(getattr(report, "propagation_results", {}).get("propagation_paths", []) or [])
            ebpf_pid = int(obs.get("agents", {}).get(aid, {}).get("_ebpf_pid", 0) or 0)
            severity = "HIGH" if risk >= 0.7 else ("MEDIUM" if risk >= 0.3 else "LOW")
            alerts.append({
                "rule": "INTER_AGENT_ANOMALY",
                "severity": severity,
                "pid": ebpf_pid or int(event_data.get("pid", 0) or 0),
                "desc": (
                    f"inter-agent 检测到 {aid} 协作异常，"
                    f"type={anomaly_type}, response={report.response_level.value}, risk={risk:.3f}"
                ),
                "agent_id": aid,
                "risk": risk,
                "object": aid,
                "details": {
                    "source": "inter_agent",
                    "anomaly_type": anomaly_type,
                    "module": module,
                    "response_level": report.response_level.value,
                    "source_agent": source_agent,
                    "anomalous_agents": anomalous_agents,
                    "event_sequence": event_lines,
                    "semantic_association": semantic_lines,
                    "root_cause": root_cause,
                    "analysis_report": analysis_report,
                    "view": view_lines,
                    "propagation_paths": propagation_paths,
                    "state_view": getattr(report, "state_view", {}) or {},
                },
            })
        return alerts

    def run_analysis(self, event_data):
        _aid, now_ns = self._update_from_event(event_data)
        obs = self._observation(now_ns)
        if len(obs["agents"]) < 1:
            return []
        try:
            report = self.agent.process_observation(obs)
        except Exception as exc:
            logger.warning("MonitorAgent processing failed: %s", exc)
            return []
        return self._report_to_alerts(report, obs, event_data, now_ns)


def run_once():
    from inter_agent.monitor.agent import MonitorAgent
    from inter_agent.data.simulator import Simulator
    from inter_agent.config import load_config

    config = load_config()
    config["llm"]["enabled"] = False
    agent = MonitorAgent(config=config)
    sim = Simulator(num_agents=4, seed=42)
    obs = sim.generate_normal()
    sim.inject_resource_anomaly(obs, "agent_2")
    report = agent.process_observation(obs)
    print(f"Response: {report.response_level.value}, risk={report.max_risk:.3f}")
    print(f"Anomalous nodes: {report.anomalous_nodes}")
    return report


def run_simulate():
    from inter_agent.monitor.agent import MonitorAgent
    from inter_agent.data.simulator import Simulator
    from inter_agent.config import load_config
    import time

    config = load_config()
    config["llm"]["enabled"] = False
    agent = MonitorAgent(config=config)
    sim = Simulator(num_agents=4, seed=42)

    for step in range(20):
        obs = sim.generate_normal()
        if step == 10:
            sim.inject_resource_anomaly(obs, "agent_2")
        report = agent.process_observation(obs)
        anom = "!" if report.anomalous_nodes else "."
        print(f"  step {step:2d}{anom} risk={report.max_risk:.3f} nodes={report.anomalous_nodes}")
        time.sleep(0.1)

    print("Done.")


def run_loop():
    from inter_agent.monitor.agent import MonitorAgent
    from inter_agent.config import load_config

    config = load_config()
    agent = MonitorAgent(config=config)
    logger.info("Inter-agent analyzer started. Waiting for observations...")

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down.")


def run_live(redis_host="127.0.0.1", redis_port=6379, window_seconds=30):
    """Real-time polling from Redis (eBPF data pipeline).

    Connects to Redis, polls inter:metric:{agent_id} keys every window_seconds,
    processes each observation through the full 5-detector pipeline,
    and outputs alert logs.

    Usage:
        python -m inter_agent.main --live --redis-host 127.0.0.1 --window 30
    """
    from inter_agent.monitor.agent import MonitorAgent
    from inter_agent.data.collector import RedisCollector
    from inter_agent.config import load_config
    import time

    config = load_config()
    config["llm"]["enabled"] = False
    agent = MonitorAgent(config=config)

    collector = RedisCollector(
        host=redis_host, port=redis_port, window_seconds=window_seconds,
    )
    logger.info("Inter-agent live analyzer started. Polling Redis %s:%d every %ds",
                redis_host, redis_port, window_seconds)

    step = 0
    try:
        while True:
            t0 = time.time()
            try:
                obs = collector.get_observation()
            except Exception as e:
                logger.warning("Redis read failed: %s", e)
                time.sleep(window_seconds)
                continue

            if not obs.get("agents"):
                time.sleep(window_seconds)
                continue

            report = agent.process_observation(obs)
            step += 1
            anom = "ALERT" if report.anomalous_nodes else "PASS"
            logger.info("[%4d] %s risk=%.3f level=%s nodes=%s",
                        step, anom, report.max_risk,
                        report.response_level.value, report.anomalous_nodes)
            dt = time.time() - t0
            sleep = max(0, window_seconds - dt)
            time.sleep(sleep)
    except KeyboardInterrupt:
        logger.info("Shutting down after %d observations.", step)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inter-agent anomaly detection")
    parser.add_argument("--once", action="store_true", help="Single-shot detection")
    parser.add_argument("--simulate", action="store_true", help="Run with simulated data")
    parser.add_argument("--live", action="store_true",
                        help="Real-time Redis polling (eBPF pipeline)")
    parser.add_argument("--redis-host", default="127.0.0.1", help="Redis host")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    parser.add_argument("--window", type=int, default=30,
                        help="Polling interval in seconds")
    args = parser.parse_args()

    if args.live:
        run_live(redis_host=args.redis_host, redis_port=args.redis_port,
                 window_seconds=args.window)
    elif args.simulate:
        run_simulate()
    elif args.once:
        run_once()
    else:
        run_loop()
