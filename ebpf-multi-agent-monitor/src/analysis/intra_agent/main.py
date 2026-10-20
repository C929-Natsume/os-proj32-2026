#!/usr/bin/env python3
import os
from collections import deque

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

EVENT_EXECVE = 1
EVENT_FORK = 2
EVENT_OPEN = 3
EVENT_UNLINK = 4
EVENT_CONNECT = 5
EVENT_SSL_READ = 6
EVENT_SSL_WRITE = 7
EVENT_CHMOD = 8
EVENT_AGENT_COMM = 9
EVENT_STDIO_READ = 10
EVENT_STDIO_WRITE = 11
EVENT_TCP_SEND = 12
EVENT_TCP_RECV = 13


class IntraAgentAnalyzer:
    def __init__(self):
        print("[INTRA] 初始化单体分析器...")
        self.workspace_root = os.environ.get("MONITOR_WORKSPACE", "/mnt/e/os2026")
        self.sensitive_markers = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/var/run/docker.sock",
            "/proc/kcore",
            "/.ssh/",
            "/.aws/credentials",
            "/.kube/config",
            ".env",
        ]
        self.shell_bins = {"sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh"}
        self.agent_stats = {}
        self.req_seq = 0

        self.loop_window_ns = 30 * 1_000_000_000
        self.loop_alert_cooldown_ns = 30 * 1_000_000_000
        self.event_alert_cooldown_ns = 5 * 1_000_000_000
        self.max_file_samples = 8

        self._load_workspace_from_config()
        print(f"[INTRA] 工作区根路径: {self.workspace_root}")

    def _load_workspace_from_config(self):
        cfg_path = os.path.join(os.path.dirname(__file__), "../../config/app_config.yaml")
        if not yaml or not os.path.exists(cfg_path):
            return
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            ws = ((cfg.get("monitor") or {}).get("workspace_root") or "").strip()
            if ws:
                self.workspace_root = ws
        except Exception as e:
            print(f"[INTRA] 读取配置失败，使用默认工作区: {e}")

    def _new_stats(self, pid, ts_ns, comm):
        return {
            "pid": pid,
            "comm": comm,
            "window_start_ns": ts_ns,
            "last_loop_alert_ns": 0,
            "last_sensitive_alert_ns": 0,
            "last_workspace_alert_ns": 0,
            "last_shell_alert_ns": 0,
            "proc_exec_cnt": 0,
            "fs_open_cnt": 0,
            "fs_unlink_cnt": 0,
            "net_connect_cnt": 0,
            "net_tcp_send_cnt": 0,
            "net_tcp_recv_cnt": 0,
            "ssl_read_cnt": 0,
            "ssl_write_cnt": 0,
            "stdio_read_cnt": 0,
            "stdio_write_cnt": 0,
            "unique_files": deque(maxlen=self.max_file_samples),
        }

    def _get_stats(self, pid, ts_ns, comm):
        s = self.agent_stats.get(pid)
        if s is None:
            s = self._new_stats(pid, ts_ns, comm)
            self.agent_stats[pid] = s
        if ts_ns - s["window_start_ns"] >= self.loop_window_ns:
            s["window_start_ns"] = ts_ns
            s["proc_exec_cnt"] = 0
            s["fs_open_cnt"] = 0
            s["fs_unlink_cnt"] = 0
            s["net_connect_cnt"] = 0
            s["net_tcp_send_cnt"] = 0
            s["net_tcp_recv_cnt"] = 0
            s["ssl_read_cnt"] = 0
            s["ssl_write_cnt"] = 0
            s["stdio_read_cnt"] = 0
            s["stdio_write_cnt"] = 0
            s["unique_files"].clear()
        return s

    def _path_is_sensitive(self, path):
        if not path:
            return False
        return any(marker in path for marker in self.sensitive_markers)

    def _path_is_workspace_or_tmp(self, path):
        if not path:
            return True
        if not path.startswith("/"):
            return True
        return (
            path.startswith(self.workspace_root)
            or path.startswith("/tmp/")
            or path.startswith("/var/tmp/")
        )

    def _is_shell_exec(self, path):
        base = os.path.basename(path or "")
        return base in self.shell_bins

    def _remember_file(self, s, path):
        if not path:
            return
        if path in s["unique_files"]:
            return
        s["unique_files"].append(path)

    def _build_req(self, event_data, rule, obj, reason, severity):
        self.req_seq += 1
        return {
            "req_id": self.req_seq,
            "timestamp_ns": int(event_data.get("timestamp", 0)),
            "pid": int(event_data.get("pid", 0)),
            "tid": int(event_data.get("pid", 0)),
            "uid": int(event_data.get("uid", 0)),
            "comm": event_data.get("comm", "unknown"),
            "rule": rule,
            "object": obj or "-",
            "reason": reason,
            "severity": severity,
        }

    def _maybe_loop_req(self, event_data, s):
        io_cnt = s["fs_open_cnt"] + s["fs_unlink_cnt"] + s["stdio_read_cnt"] + s["stdio_write_cnt"]
        net_cnt = s["net_connect_cnt"] + s["ssl_read_cnt"] + s["ssl_write_cnt"] + s["net_tcp_send_cnt"] + s["net_tcp_recv_cnt"]
        ts_ns = int(event_data.get("timestamp", 0))
        if io_cnt < 120 or net_cnt < 120:
            return None
        if len(s["unique_files"]) > 3:
            return None
        if ts_ns - s["last_loop_alert_ns"] < self.loop_alert_cooldown_ns:
            return None
        s["last_loop_alert_ns"] = ts_ns
        return self._build_req(
            event_data,
            "POSSIBLE_LOGIC_LOOP",
            "-",
            "文件与网络操作高频且对象集中，疑似逻辑循环",
            "MEDIUM",
        )

    def analyze_event(self, event_data):
        reqs = []
        event_type = int(event_data.get("type", 0))
        pid = int(event_data.get("pid", 0))
        ts_ns = int(event_data.get("timestamp", 0))
        comm = event_data.get("comm", "unknown")
        path = event_data.get("filename", "") or ""
        s = self._get_stats(pid, ts_ns, comm)

        if event_type == EVENT_EXECVE:
            s["proc_exec_cnt"] += 1
            if self._is_shell_exec(path) and ts_ns - s["last_shell_alert_ns"] >= self.event_alert_cooldown_ns:
                s["last_shell_alert_ns"] = ts_ns
                reqs.append(
                    self._build_req(
                        event_data,
                        "UNEXPECTED_SHELL_EXEC",
                        path,
                        "检测到进程执行 shell 解释器",
                        "HIGH",
                    )
                )

        elif event_type == EVENT_OPEN:
            s["fs_open_cnt"] += 1
            self._remember_file(s, path)
            if self._path_is_sensitive(path) and ts_ns - s["last_sensitive_alert_ns"] >= self.event_alert_cooldown_ns:
                s["last_sensitive_alert_ns"] = ts_ns
                reqs.append(
                    self._build_req(
                        event_data,
                        "SENSITIVE_FILE_ACCESS",
                        path,
                        "检测到敏感路径访问",
                        "HIGH",
                    )
                )

        elif event_type == EVENT_UNLINK:
            s["fs_unlink_cnt"] += 1
            self._remember_file(s, path)
            if self._path_is_sensitive(path) and ts_ns - s["last_sensitive_alert_ns"] >= self.event_alert_cooldown_ns:
                s["last_sensitive_alert_ns"] = ts_ns
                reqs.append(
                    self._build_req(
                        event_data,
                        "SENSITIVE_FILE_ACCESS",
                        path,
                        "检测到敏感路径删除",
                        "HIGH",
                    )
                )
            if (
                not self._path_is_workspace_or_tmp(path)
                and ts_ns - s["last_workspace_alert_ns"] >= self.event_alert_cooldown_ns
            ):
                s["last_workspace_alert_ns"] = ts_ns
                reqs.append(
                    self._build_req(
                        event_data,
                        "OUT_OF_WORKSPACE_OPERATION",
                        path,
                        "检测到工作区外删除行为",
                        "HIGH",
                    )
                )

        elif event_type == EVENT_CONNECT:
            # 基础计数
            s["net_connect_cnt"] += 1
            
            # 【新增】：提取 C 语言传过来的网络目标，可以留作后续大模型威胁情报查询的物料
            dip = event_data.get('dip', '0.0.0.0')
            dport = event_data.get('dport', 0)
            
            # 防刷屏控制：每 5 秒最多报一次可疑网络连接
            if ts_ns - s.get("last_network_alert_ns", 0) >= self.event_alert_cooldown_ns:
                s["last_network_alert_ns"] = ts_ns
                # 记录这通报的连接详情
                net_info = f"{dip}:{dport}"
                # 如果检测到非标准的 HTTP(80) / HTTPS(443) 端口连接，可以触发低级别告警给 LLM 分析
                if dport not in [80, 443]:
                    reqs.append(
                        self._build_req(
                            event_data,
                            "UNUSUAL_NETWORK_CONNECTION",
                            net_info,
                            f"检测到非标端口外连请求: {net_info}",
                            "MEDIUM",
                        )
                    )

        elif event_type == EVENT_SSL_READ:
            s["ssl_read_cnt"] += 1

        elif event_type == EVENT_SSL_WRITE:
            s["ssl_write_cnt"] += 1

        elif event_type == EVENT_CHMOD:
            s["fs_open_cnt"] += 1
            self._remember_file(s, path)

        elif event_type == EVENT_AGENT_COMM:
            s["net_connect_cnt"] += 1

        elif event_type in (EVENT_STDIO_READ, EVENT_STDIO_WRITE):
            if event_type == EVENT_STDIO_READ:
                s["stdio_read_cnt"] += 1
            else:
                s["stdio_write_cnt"] += 1

        elif event_type in (EVENT_TCP_SEND, EVENT_TCP_RECV):
            if event_type == EVENT_TCP_SEND:
                s["net_tcp_send_cnt"] += 1
            else:
                s["net_tcp_recv_cnt"] += 1

        loop_req = self._maybe_loop_req(event_data, s)
        if loop_req is not None:
            reqs.append(loop_req)
        return reqs


if __name__ == "__main__":
    analyzer = IntraAgentAnalyzer()
    demo_event = {
        "type": EVENT_EXECVE,
        "pid": 1234,
        "uid": 1000,
        "timestamp": 1234567890000000000,
        "comm": "agent",
        "filename": "/bin/bash",
    }
    print(analyzer.analyze_event(demo_event))
