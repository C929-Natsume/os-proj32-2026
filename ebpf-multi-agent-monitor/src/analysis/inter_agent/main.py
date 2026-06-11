#!/usr/bin/env python3
import os
import ipaddress
import re
import sys
import time
from collections import defaultdict, deque

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EVENT_EXECVE = 1
EVENT_FORK = 2
EVENT_OPEN = 3
EVENT_UNLINK = 4
EVENT_CONNECT = 5
EVENT_SSL_READ = 6
EVENT_SSL_WRITE = 7


class InterAgentAnalyzer:
    def __init__(self):
        print("[INTER] Initializing Inter-Agent Analyzer...")
        self.workspace_root = os.environ.get("MONITOR_WORKSPACE", "/mnt/e/os2026")
        self.home_dir = os.path.expanduser("~")
        self.window_ns = 30 * 1_000_000_000
        self.correlation_window_ns = 15 * 1_000_000_000
        self.cooldown_ns = 5 * 1_000_000_000
        self.high_api_connect_threshold = 20
        self.fork_threshold = 10
        self.io_storm_threshold = 40
        self.short_ssl_len_threshold = 64
        self.short_ssl_burst_threshold = 12
        self.repeat_payload_threshold = 3
        self.resource_contention_active_agents = 4
        self.resource_contention_event_threshold = 120
        self.allowed_ports = {80, 443}
        self.allowed_private_networks = self._parse_networks(
            ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        )
        self.sensitive_path_markers = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/var/run/docker.sock",
            "/.ssh/",
            "/.aws/credentials",
            "/.kube/config",
            ".env",
        ]
        self.shell_bins = {"sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh"}
        self.interpreter_bins = {"sh", "bash", "zsh", "python", "python3", "perl", "ruby", "node", "php"}
        self.download_bins = {"curl", "wget"}
        self.prompt_injection_markers = [
            "ignore previous instructions",
            "ignore all previous instructions",
            "system prompt",
            "developer message",
            "reveal secrets",
            "bypass",
            "jailbreak",
        ]
        self.high_risk_instruction_markers = [
            "rm -rf",
            "delete all files",
            "sudo reboot",
            "sudo rm",
            "chmod 777",
            "curl http",
            "wget http",
            "/etc/shadow",
            "id_rsa",
        ]
        self.loop_markers = ["continue", "retry", "again", "repeat", "try again"]
        self.mining_markers = ["xmrig", "stratum", "cryptonight", "miner"]
        self.benign_read_prefixes = [
            "/proc/",
            "/sys/",
        ]
        self.benign_state_prefixes = [
            os.path.join(self.home_dir, ".claude") + "/",
            os.path.join(self.home_dir, ".codex") + "/",
            os.path.join(self.home_dir, ".gemini") + "/",
            os.path.join(self.home_dir, ".config", "gemini") + "/",
        ]

        self._load_rules()

        self.agent_graph = defaultdict(set)
        self.agent_activities = defaultdict(lambda: deque(maxlen=100))
        self.agent_stats = {}
        self.global_events = deque()

        self.last_alert_time = defaultdict(int)

        print("[INTER] Inter-Agent Analyzer initialized")

    def _load_rules(self):
        rules_file = os.path.join(os.path.dirname(__file__), "../../config/rules.yaml")
        if not yaml or not os.path.exists(rules_file):
            return
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                rules = yaml.safe_load(f) or {}
            cfg = rules.get("inter_agent") or {}
            self.window_ns = int(cfg.get("window_sec", 30) or 30) * 1_000_000_000
            self.correlation_window_ns = int(cfg.get("correlation_window_sec", 15) or 15) * 1_000_000_000
            self.cooldown_ns = int(cfg.get("cooldown_sec", 5) or 5) * 1_000_000_000
            self.high_api_connect_threshold = int(cfg.get("high_api_connect_threshold", 20) or 20)
            self.fork_threshold = int(cfg.get("fork_threshold", 10) or 10)
            self.io_storm_threshold = int(cfg.get("io_storm_threshold", 40) or 40)
            self.short_ssl_len_threshold = int(cfg.get("short_ssl_len_threshold", 64) or 64)
            self.short_ssl_burst_threshold = int(cfg.get("short_ssl_burst_threshold", 12) or 12)
            self.repeat_payload_threshold = int(cfg.get("repeat_payload_threshold", 3) or 3)
            self.resource_contention_active_agents = int(
                cfg.get("resource_contention_active_agents", 4) or 4
            )
            self.resource_contention_event_threshold = int(
                cfg.get("resource_contention_event_threshold", 120) or 120
            )
            workspace_root = str(cfg.get("workspace_root", self.workspace_root) or self.workspace_root).strip()
            if workspace_root:
                self.workspace_root = workspace_root
            self.allowed_ports = {int(p) for p in cfg.get("allowed_ports", sorted(self.allowed_ports))}
            self.allowed_private_networks = self._parse_networks(
                cfg.get(
                    "allowed_private_cidrs",
                    ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                )
            )
            self.sensitive_path_markers = list(
                cfg.get("sensitive_path_markers", self.sensitive_path_markers)
            )
            self.shell_bins = {str(v) for v in cfg.get("shell_bins", list(self.shell_bins))}
            self.interpreter_bins = {str(v) for v in cfg.get("interpreter_bins", list(self.interpreter_bins))}
            self.download_bins = {str(v) for v in cfg.get("download_bins", list(self.download_bins))}
            self.prompt_injection_markers = [
                str(v).lower() for v in cfg.get("prompt_injection_markers", self.prompt_injection_markers)
            ]
            self.high_risk_instruction_markers = [
                str(v).lower() for v in cfg.get("high_risk_instruction_markers", self.high_risk_instruction_markers)
            ]
            self.loop_markers = [str(v).lower() for v in cfg.get("loop_markers", self.loop_markers)]
            self.mining_markers = [str(v).lower() for v in cfg.get("mining_markers", self.mining_markers)]
            self.benign_read_prefixes = list(
                cfg.get("benign_read_prefixes", self.benign_read_prefixes)
            )
            self.benign_state_prefixes = list(
                cfg.get("benign_state_prefixes", self.benign_state_prefixes)
            )
        except Exception as e:
            print(f"[INTER] Failed to load inter-agent rules, using defaults: {e}")

    @staticmethod
    def _parse_networks(items):
        networks = []
        for item in items:
            try:
                networks.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError:
                continue
        return networks

    def _new_stats(self, pid, ts_ns):
        return {
            "pid": pid,
            "window_start_ns": ts_ns,
            "fork_count": 0,
            "connect_count": 0,
            "short_ssl_count": 0,
            "recent_execs": deque(maxlen=8),
            "path_counts": defaultdict(int),
            "payload_counts": defaultdict(int),
            "last_download_exec_ns": 0,
            "last_high_risk_prompt_ns": 0,
            "last_prompt_injection_ns": 0,
            "last_loop_signal_ns": 0,
        }

    def _get_stats(self, pid, ts_ns):
        stats = self.agent_stats.get(pid)
        if stats is None:
            stats = self._new_stats(pid, ts_ns)
            self.agent_stats[pid] = stats
            return stats
        if ts_ns - stats["window_start_ns"] >= self.window_ns:
            stats = self._new_stats(pid, ts_ns)
            self.agent_stats[pid] = stats
        return stats

    def _record_global_event(self, ts_ns, pid, event_type):
        self.global_events.append((ts_ns, pid, event_type))
        cutoff = ts_ns - self.window_ns
        while self.global_events and self.global_events[0][0] < cutoff:
            self.global_events.popleft()

    def _emit_alert(self, current_ts_ns, key, rule, pid, severity, desc):
        if current_ts_ns - self.last_alert_time[key] < self.cooldown_ns:
            return None
        self.last_alert_time[key] = current_ts_ns
        return {
            "rule": rule,
            "pid": pid,
            "severity": severity,
            "desc": desc,
        }

    def _path_is_sensitive(self, path):
        return bool(path) and any(marker in path for marker in self.sensitive_path_markers)

    def _path_is_outside_workspace(self, path):
        if not path or not path.startswith("/"):
            return False
        return not (
            path.startswith(self.workspace_root)
            or path.startswith("/tmp/")
            or path.startswith("/var/tmp/")
        )

    def _path_is_benign_read(self, path):
        if not path:
            return False
        return any(path.startswith(prefix) for prefix in self.benign_read_prefixes)

    def _path_is_benign_state(self, path):
        if not path:
            return False
        return any(path.startswith(prefix) for prefix in self.benign_state_prefixes)

    @staticmethod
    def _is_invalid_endpoint(dip, dport):
        return not dip or dip == "0.0.0.0" or int(dport or 0) <= 0

    @staticmethod
    def _normalize_text(text):
        normalized = re.sub(r"\s+", " ", (text or "").strip().lower())
        return normalized[:512]

    def _contains_any(self, text, markers):
        lowered = (text or "").lower()
        return any(marker in lowered for marker in markers)

    def _looks_repetitive_text(self, text):
        normalized = self._normalize_text(text)
        if len(normalized) < 64:
            return False
        words = normalized.split()
        if len(words) < 12:
            return False
        unique_ratio = len(set(words)) / max(len(words), 1)
        if unique_ratio < 0.2:
            return True
        repeated_phrases = re.findall(r"(.{12,40}?)\1{2,}", normalized)
        return bool(repeated_phrases)

    def _ip_allowed(self, dip):
        try:
            ip = ipaddress.ip_address(dip)
        except ValueError:
            return True
        if not ip.is_private and not ip.is_loopback:
            return False
        return any(ip in network for network in self.allowed_private_networks)

    def _analyze_execve(self, event_data, stats, current_ts_ns):
        alerts = []
        path = event_data.get("filename", "") or ""
        base = os.path.basename(path)
        pid = event_data.get("pid", 0)
        stats["recent_execs"].append((current_ts_ns, base, path))

        if base in self.download_bins:
            stats["last_download_exec_ns"] = current_ts_ns

        if base == "sudo":
            alert = self._emit_alert(
                current_ts_ns,
                f"sudo:{pid}",
                "PRIVILEGE_ESCALATION_ATTEMPT",
                pid,
                "CRITICAL",
                f"Agent PID={pid} 尝试执行 sudo: {path}",
            )
            if alert:
                alerts.append(alert)

        if base in self.interpreter_bins and current_ts_ns - stats["last_download_exec_ns"] <= self.correlation_window_ns:
            alert = self._emit_alert(
                current_ts_ns,
                f"download_exec:{pid}",
                "SUSPICIOUS_DOWNLOAD_EXEC_CHAIN",
                pid,
                "HIGH",
                f"Agent PID={pid} 出现下载后执行链路: {path}",
            )
            if alert:
                alerts.append(alert)

        if base in self.shell_bins:
            alert = self._emit_alert(
                current_ts_ns,
                f"shell:{pid}",
                "UNEXPECTED_SHELL_EXEC_CHAIN",
                pid,
                "HIGH",
                f"Agent PID={pid} 启动了非预期 shell: {path}",
            )
            if alert:
                alerts.append(alert)
            if current_ts_ns - stats["last_high_risk_prompt_ns"] <= self.correlation_window_ns:
                alert = self._emit_alert(
                    current_ts_ns,
                    f"prompt_shell:{pid}",
                    "PROMPT_INJECTION_TO_DANGEROUS_ACTION",
                    pid,
                    "CRITICAL",
                    f"Agent PID={pid} 在高危提示后执行 shell: {path}",
                )
                if alert:
                    alerts.append(alert)

        return alerts

    def _analyze_file_event(self, event_data, stats, current_ts_ns):
        alerts = []
        path = event_data.get("filename", "") or ""
        pid = event_data.get("pid", 0)
        event_type = event_data.get("type", 0)
        stats["path_counts"][path] += 1
        path_count = stats["path_counts"][path]

        if self._path_is_sensitive(path):
            alert = self._emit_alert(
                current_ts_ns,
                f"sensitive:{pid}:{path}",
                "SENSITIVE_FILE_OUT_OF_SCOPE",
                pid,
                "CRITICAL",
                f"Agent PID={pid} 访问敏感路径: {path}",
            )
            if alert:
                alerts.append(alert)

        if "../" in path:
            alert = self._emit_alert(
                current_ts_ns,
                f"traversal:{pid}:{path}",
                "PATH_TRAVERSAL_ATTEMPT",
                pid,
                "HIGH",
                f"Agent PID={pid} 尝试路径遍历: {path}",
            )
            if alert:
                alerts.append(alert)

        outside_workspace = self._path_is_outside_workspace(path)
        if event_type == EVENT_OPEN and self._path_is_benign_read(path):
            outside_workspace = False
        if event_type == EVENT_UNLINK and self._path_is_benign_state(path):
            outside_workspace = False

        if outside_workspace:
            rule = "OUT_OF_WORKSPACE_DELETE" if event_type == EVENT_UNLINK else "OUT_OF_WORKSPACE_ACCESS"
            action = "删除" if event_type == EVENT_UNLINK else "访问"
            alert = self._emit_alert(
                current_ts_ns,
                f"outside:{pid}:{rule}:{path}",
                rule,
                pid,
                "HIGH",
                f"Agent PID={pid} 在工作区外{action}文件: {path}",
            )
            if alert:
                alerts.append(alert)

        if path_count >= self.io_storm_threshold:
            alert = self._emit_alert(
                current_ts_ns,
                f"io_storm:{pid}:{path}",
                "FILE_IO_STORM",
                pid,
                "HIGH",
                f"Agent PID={pid} 对同一路径高频操作，疑似 I/O 风暴: {path}",
            )
            if alert:
                alerts.append(alert)
            if current_ts_ns - stats["last_loop_signal_ns"] <= self.correlation_window_ns:
                alert = self._emit_alert(
                    current_ts_ns,
                    f"hallucination_io:{pid}:{path}",
                    "HALLUCINATION_INDUCED_LOOP",
                    pid,
                    "HIGH",
                    f"Agent PID={pid} 出现重复语义信号并伴随文件风暴: {path}",
                )
                if alert:
                    alerts.append(alert)

        if current_ts_ns - stats["last_high_risk_prompt_ns"] <= self.correlation_window_ns:
            alert = self._emit_alert(
                current_ts_ns,
                f"prompt_file:{pid}:{path}",
                "PROMPT_INJECTION_TO_DANGEROUS_ACTION",
                pid,
                "CRITICAL",
                f"Agent PID={pid} 在高危提示后触发文件操作: {path}",
            )
            if alert:
                alerts.append(alert)

        return alerts

    def _analyze_connect(self, event_data, stats, current_ts_ns):
        alerts = []
        pid = event_data.get("pid", 0)
        dip = event_data.get("dip", "") or ""
        dport = int(event_data.get("dport", 0) or 0)

        if self._is_invalid_endpoint(dip, dport):
            return alerts

        stats["connect_count"] += 1

        if stats["connect_count"] >= self.high_api_connect_threshold:
            alert = self._emit_alert(
                current_ts_ns,
                f"api_burst:{pid}",
                "HIGH_FREQUENCY_API_CALLS",
                pid,
                "HIGH",
                f"Agent PID={pid} 在短时间内发起 {stats['connect_count']} 次网络连接",
            )
            if alert:
                alerts.append(alert)

        try:
            ip = ipaddress.ip_address(dip)
        except ValueError:
            ip = None

        if ip is not None and ip.is_private and not self._ip_allowed(dip):
            alert = self._emit_alert(
                current_ts_ns,
                f"internal_conn:{pid}:{dip}",
                "NON_WHITELIST_INTERNAL_CONNECTION",
                pid,
                "HIGH",
                f"Agent PID={pid} 连接了非白名单内网地址: {dip}:{dport}",
            )
            if alert:
                alerts.append(alert)

        if dport and dport not in self.allowed_ports:
            alert = self._emit_alert(
                current_ts_ns,
                f"odd_port:{pid}:{dip}:{dport}",
                "UNUSUAL_EXTERNAL_CONNECTION",
                pid,
                "MEDIUM",
                f"Agent PID={pid} 连接了异常端口: {dip}:{dport}",
            )
            if alert:
                alerts.append(alert)

        if current_ts_ns - stats["last_high_risk_prompt_ns"] <= self.correlation_window_ns:
            alert = self._emit_alert(
                current_ts_ns,
                f"prompt_net:{pid}:{dip}:{dport}",
                "PROMPT_INJECTION_TO_DANGEROUS_ACTION",
                pid,
                "CRITICAL",
                f"Agent PID={pid} 在高危提示后发起外联: {dip}:{dport}",
            )
            if alert:
                alerts.append(alert)

        return alerts

    def _analyze_ssl(self, event_data, stats, current_ts_ns):
        alerts = []
        pid = event_data.get("pid", 0)
        data = event_data.get("data", "") or ""
        data_len = int(event_data.get("data_len", 0) or 0)
        normalized = self._normalize_text(data)

        if data_len <= self.short_ssl_len_threshold:
            stats["short_ssl_count"] += 1
            if stats["short_ssl_count"] >= self.short_ssl_burst_threshold:
                alert = self._emit_alert(
                    current_ts_ns,
                    f"short_ssl:{pid}",
                    "FREQUENT_SHORT_SSL_SESSIONS",
                    pid,
                    "MEDIUM",
                    f"Agent PID={pid} 出现高频短 SSL 明文片段，疑似异常短会话/重试",
                )
                if alert:
                    alerts.append(alert)

        if normalized:
            stats["payload_counts"][normalized] += 1
            if stats["payload_counts"][normalized] >= self.repeat_payload_threshold and (
                self._contains_any(normalized, self.loop_markers) or self._looks_repetitive_text(normalized)
            ):
                stats["last_loop_signal_ns"] = current_ts_ns
                alert = self._emit_alert(
                    current_ts_ns,
                    f"loop_payload:{pid}",
                    "HALLUCINATION_INDUCED_LOOP",
                    pid,
                    "HIGH",
                    f"Agent PID={pid} 出现重复无进展语义片段，疑似幻觉诱导循环",
                )
                if alert:
                    alerts.append(alert)

        if self._contains_any(normalized, self.prompt_injection_markers):
            stats["last_prompt_injection_ns"] = current_ts_ns
            alert = self._emit_alert(
                current_ts_ns,
                f"prompt_injection:{pid}",
                "PROMPT_INJECTION_SIGNAL",
                pid,
                "HIGH",
                f"Agent PID={pid} 的 SSL 明文中出现提示注入特征",
            )
            if alert:
                alerts.append(alert)

        if self._contains_any(normalized, self.high_risk_instruction_markers):
            stats["last_high_risk_prompt_ns"] = current_ts_ns
            alert = self._emit_alert(
                current_ts_ns,
                f"high_risk_prompt:{pid}",
                "HIGH_RISK_INSTRUCTION_IN_SSL",
                pid,
                "CRITICAL",
                f"Agent PID={pid} 的 SSL 明文中出现高危操作指令",
            )
            if alert:
                alerts.append(alert)

        if self._contains_any(normalized, self.mining_markers):
            alert = self._emit_alert(
                current_ts_ns,
                f"mining:{pid}",
                "FUNCTION_MISUSE_MINING_SIGNAL",
                pid,
                "HIGH",
                f"Agent PID={pid} 的 SSL 明文中出现疑似挖矿/滥用指令",
            )
            if alert:
                alerts.append(alert)

        if self._looks_repetitive_text(normalized):
            alert = self._emit_alert(
                current_ts_ns,
                f"repetitive_ssl:{pid}",
                "SUSPICIOUS_REPETITIVE_SSL_PAYLOAD",
                pid,
                "MEDIUM",
                f"Agent PID={pid} 的 SSL 明文出现超长重复文本",
            )
            if alert:
                alerts.append(alert)

        return alerts

    def analyze_multi_agent(self, event_data):
        pid = int(event_data.get("pid", 0) or 0)
        ppid = int(event_data.get("ppid", 0) or 0)
        event_type = int(event_data.get("type", 0) or 0)
        current_ts_ns = int(event_data.get("timestamp", int(time.time() * 1e9)) or int(time.time() * 1e9))
        stats = self._get_stats(pid, current_ts_ns)

        if ppid and ppid != pid:
            self.agent_graph[ppid].add(pid)
        if event_type == EVENT_FORK and pid:
            stats["fork_count"] += 1

        self.agent_activities[pid].append(event_data)
        self._record_global_event(current_ts_ns, pid, event_type)

        alerts = []
        if event_type == EVENT_EXECVE:
            alerts.extend(self._analyze_execve(event_data, stats, current_ts_ns))
        elif event_type in (EVENT_OPEN, EVENT_UNLINK):
            alerts.extend(self._analyze_file_event(event_data, stats, current_ts_ns))
        elif event_type == EVENT_CONNECT:
            alerts.extend(self._analyze_connect(event_data, stats, current_ts_ns))
        elif event_type in (EVENT_SSL_READ, EVENT_SSL_WRITE):
            alerts.extend(self._analyze_ssl(event_data, stats, current_ts_ns))

        alerts.extend(self.check_cross_agent_anomalies(current_ts_ns))
        return alerts

    def check_cross_agent_anomalies(self, current_ts_ns):
        alerts = []

        for pid, stats in list(self.agent_stats.items()):
            if stats["connect_count"] > self.high_api_connect_threshold:
                alert = self._emit_alert(
                    current_ts_ns,
                    f"scan:{pid}",
                    "POTENTIAL_PORT_SCAN",
                    pid,
                    "HIGH",
                    f"Agent PID={pid} 异常发起 {stats['connect_count']} 次网络连接",
                )
                if alert:
                    alerts.append(alert)

        for parent, children in list(self.agent_graph.items()):
            child_count = len(children)
            if child_count > self.fork_threshold:
                alert = self._emit_alert(
                    current_ts_ns,
                    f"fork:{parent}",
                    "POTENTIAL_FORK_BOMB",
                    parent,
                    "CRITICAL",
                    f"Agent PID={parent} 异常派生了 {child_count} 个子进程/分支",
                )
                if alert:
                    alerts.append(alert)

        for pid, stats in list(self.agent_stats.items()):
            if stats["fork_count"] > self.fork_threshold:
                alert = self._emit_alert(
                    current_ts_ns,
                    f"fork_rate:{pid}",
                    "POTENTIAL_FORK_BOMB",
                    pid,
                    "CRITICAL",
                    f"Agent PID={pid} 在窗口内触发了 {stats['fork_count']} 次 fork，疑似 fork bomb",
                )
                if alert:
                    alerts.append(alert)

        active_pids = {pid for ts_ns, pid, _ in self.global_events if current_ts_ns - ts_ns <= self.window_ns}
        if (
            len(active_pids) >= self.resource_contention_active_agents
            and len(self.global_events) >= self.resource_contention_event_threshold
        ):
            alert = self._emit_alert(
                current_ts_ns,
                "resource_contention:global",
                "RESOURCE_CONTENTION_SPIKE",
                0,
                "HIGH",
                f"检测到 {len(active_pids)} 个活跃 agent/进程同时产生高密度事件，疑似资源争抢",
            )
            if alert:
                alerts.append(alert)

        return alerts

    def find_suspicious_pairs(self):
        # 预留给未来复杂图谱分析的接口
        pass

    def run_analysis(self, event_data):
        # 运行分析并返回产生的告警列表（如果没有告警，则返回空列表）
        alerts = self.analyze_multi_agent(event_data)
        return alerts


if __name__ == "__main__":
    print("=" * 60)
    print("[INTER] eBPF Multi-Agent Monitor - Inter-Agent Analyzer (Test Mode)")
    print("=" * 60)

    analyzer = InterAgentAnalyzer()

    # 模拟 Fork 炸弹测试
    print("\n>>> Testing Fork Bomb Detection")
    for i in range(15):
        test_event = {
            'type': 2,
            'pid': 5000 + i,
            'ppid': 1234,
            'comm': 'malicious_sh',
            'timestamp': int(time.time() * 1e9) + i
        }
        res = analyzer.run_analysis(test_event)
        if res:
            print(f"ALERTS TRIGGERED: {res}")
