#!/usr/bin/env python3
import os
import sys
import time
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class InterAgentAnalyzer:
    def __init__(self):
        print("[INTER] Initializing Inter-Agent Analyzer...")
        self.agent_graph = defaultdict(list)
        
        # 【修复1：防止内存爆满】每个 PID 最多只保留最近 100 条行为记录
        self.agent_activities = defaultdict(lambda: deque(maxlen=100)) 
        
        self.correlation_count = defaultdict(int)
        
        # 【修复2：告警防刷屏】记录上一次告警的时间戳
        self.last_alert_time = defaultdict(int)
        self.cooldown_ns = 5 * 1_000_000_000  # 5秒冷却时间

        print("[INTER] Inter-Agent Analyzer initialized")

    def analyze_multi_agent(self, event_data):
        pid = event_data.get('pid', 0)
        event_type = event_data.get('type', 0)

        # 构建进程派生图 (EVENT_FORK)
        if event_type == 2:
            # 注意：这需要你的 C 代码中已经正确传出了 ppid 字段！
            parent_pid = event_data.get('ppid', 0)
            if parent_pid != 0:
                self.agent_graph[parent_pid].append(pid)

        # 统计网络连接频率 (EVENT_CONNECT)
        if event_type == 5:
            self.correlation_count[pid] += 1

        self.agent_activities[pid].append(event_data)
        
        # 返回收集到的真实异常列表
        return self.check_cross_agent_anomalies(event_data.get('timestamp', int(time.time() * 1e9)))

    def check_cross_agent_anomalies(self, current_ts_ns):
        alerts = [] # 【修复3：收集真实告警并返回】

        # 检测 1：潜在的端口扫描 (单进程极高频网络连接)
        for pid, count in list(self.correlation_count.items()):
            if count > 20: # 稍微调高阈值，防止正常浏览器被误杀
                if current_ts_ns - self.last_alert_time[f"scan_{pid}"] >= self.cooldown_ns:
                    alerts.append({
                        "rule": "POTENTIAL_PORT_SCAN",
                        "pid": pid,
                        "desc": f"Agent PID={pid} 异常发起 {count} 次网络连接",
                        "severity": "HIGH"
                    })
                    self.last_alert_time[f"scan_{pid}"] = current_ts_ns

        # 检测 2：潜在的 Fork 炸弹 (单父进程派生大量子进程)
        for parent, children in list(self.agent_graph.items()):
            if len(children) > 10:
                if current_ts_ns - self.last_alert_time[f"fork_{parent}"] >= self.cooldown_ns:
                    alerts.append({
                        "rule": "POTENTIAL_FORK_BOMB",
                        "pid": parent,
                        "desc": f"Agent PID={parent} 异常派生了 {len(children)} 个子进程",
                        "severity": "CRITICAL"
                    })
                    self.last_alert_time[f"fork_{parent}"] = current_ts_ns

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