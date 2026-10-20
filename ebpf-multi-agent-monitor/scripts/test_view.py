#!/usr/bin/env python3
"""Quick smoke test for the expanded [view] block helpers."""
import copy, json, os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(BASE)
sys.path.insert(0, os.path.dirname(PROJECT))
sys.path.insert(0, PROJECT)

import inter_agent
print("PROJECT:", PROJECT)
print("inter_agent ->", inter_agent.__file__)

from inter_agent.monitor.agent import MonitorAgent
from inter_agent.config import load_config


def make_agent():
    cfg = load_config()
    cfg["llm"] = {"enabled": False}
    model = os.path.join(PROJECT, "models", "anomaly_detector.pth")
    return MonitorAgent(config=cfg, model_path=model)


def make_obs_hier():
    agents = {f"agent_{i}": {"cpu_usage": 0.5, "memory_usage": 0.4} for i in range(5)}
    interactions = []
    # supervisor agent_0 -> each worker
    for i in range(1, 5):
        interactions.append({"src": "agent_0", "dst": f"agent_{i}", "type": "api_call",
                             "weight": 0.8, "msg_count": 3, "data_size": 512,
                             "timestamp_ns": 0})
        interactions.append({"src": "agent_0", "dst": f"agent_{i}", "type": "message",
                             "weight": 0.5, "msg_count": 2, "data_size": 64,
                             "timestamp_ns": 0})
    # one worker->supervisor reply
    interactions.append({"src": "agent_1", "dst": "agent_0", "type": "message",
                         "weight": 0.5, "msg_count": 1, "data_size": 32,
                         "timestamp_ns": 0})
    return {"agents": agents, "interactions": interactions, "messages": [],
            "_topology": "hierarchical", "timestamp": 0}


def make_obs_large():
    n = 16
    agents = {f"agent_{i}": {"cpu_usage": 0.5, "memory_usage": 0.4} for i in range(n)}
    interactions = []
    for i in range(n):
        for j in range(10):
            d = (i + j + 1) % n
            interactions.append({"src": f"agent_{i}", "dst": f"agent_{d}",
                                 "type": "api_call" if j % 2 else "message",
                                 "weight": 0.6, "msg_count": 2,
                                 "data_size": 128, "timestamp_ns": 0})
    return {"agents": agents, "interactions": interactions, "messages": [],
            "_topology": "peer-to-peer", "timestamp": 0}


def main():
    agent = make_agent()
    for name, obs in [("hier_small", make_obs_hier()), ("peer_large", make_obs_large())]:
        v = agent._analyze_view(obs, "test")
        print("=" * 60)
        print(f"  CASE: {name}")
        print("=" * 60)
        print(f"  topology={v['topology']}  agents={v['agents']}  edges={v['edges']}")
        print(f"  agents: {v['agent_list']}")
        print("  roles: " + ", ".join(f"{a}={r}" for a, r in sorted(v['roles'].items())))
        print("  responsibilities: " + "; ".join(f"{r}={d}" for r, d in v['responsibilities'].items()))
        if v["ascii"]:
            print("  --- ASCII diagram ---")
            for ln in v["ascii"].split("\n"):
                print("  " + ln)
        print("  --- edge list ---")
        for ln in v["edge_lines"]:
            print("  " + ln)
        print()


if __name__ == "__main__":
    main()
