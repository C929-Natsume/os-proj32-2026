#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class IntraAgentAnalyzer:
    def __init__(self):
        print("[INTRA] Initializing Intra-Agent Analyzer...")
        self.agent_behaviors = {}
        print("[INTRA] Intra-Agent Analyzer initialized")

    def analyze_single_agent(self, event_data):
        print(f"[INTRA] Analyzing single agent behavior for event: {event_data}")
        pid = event_data.get('pid', 0)
        comm = event_data.get('comm', 'unknown')
        event_type = event_data.get('type', 0)

        if pid not in self.agent_behaviors:
            print(f"[INTRA] New agent detected: PID={pid}, Comm={comm}")
            self.agent_behaviors[pid] = {
                'comm': comm,
                'events': [],
                'exec_count': 0,
                'file_count': 0,
                'network_count': 0
            }

        agent = self.agent_behaviors[pid]
        agent['events'].append(event_data)

        if event_type == 1:
            agent['exec_count'] += 1
            print(f"[INTRA]   Agent {pid} executed a program (exec_count={agent['exec_count']})")
        elif event_type == 3:
            agent['file_count'] += 1
            print(f"[INTRA]   Agent {pid} accessed a file (file_count={agent['file_count']})")
        elif event_type == 5:
            agent['network_count'] += 1
            print(f"[INTRA]   Agent {pid} made a network connection (network_count={agent['network_count']})")

        self.detect_anomalies(pid, agent)

        return agent

    def detect_anomalies(self, pid, agent):
        print(f"[INTRA] Checking for anomalies in agent PID={pid}...")

        if agent['exec_count'] > 50:
            print(f"[INTRA]   ANOMALY: High exec count ({agent['exec_count']}) for agent {pid}")

        if agent['file_count'] > 100:
            print(f"[INTRA]   ANOMALY: High file access count ({agent['file_count']}) for agent {pid}")

        if agent['network_count'] > 20:
            print(f"[INTRA]   ANOMALY: High network activity ({agent['network_count']}) for agent {pid}")

    def get_agent_summary(self, pid):
        if pid in self.agent_behaviors:
            print(f"[INTRA] Summary for agent PID={pid}: {self.agent_behaviors[pid]}")
            return self.agent_behaviors[pid]
        return None

    def run_analysis(self, event_data):
        print(f"[INTRA] Running intra-agent analysis on event...")
        result = self.analyze_single_agent(event_data)
        print(f"[INTRA] Intra-agent analysis complete")
        return result


if __name__ == "__main__":
    print("=" * 60)
    print("[INTRA] eBPF Multi-Agent Monitor - Intra-Agent Analyzer")
    print("=" * 60)

    analyzer = IntraAgentAnalyzer()

    test_event = {
        'type': 1,
        'pid': 1234,
        'comm': 'test_agent',
        'filename': '/bin/ls'
    }
    analyzer.run_analysis(test_event)
