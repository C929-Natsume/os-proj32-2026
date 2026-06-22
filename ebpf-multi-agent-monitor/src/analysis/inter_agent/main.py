"""Multi-agent collaborative anomaly detection entry point.

Usage:
    python -m inter_agent.main                  # run interactive loop
    python -m inter_agent.main --once           # single-shot detection
    python -m inter_agent.main --simulate       # run with simulated data
"""

import argparse
import logging
import sys

logging.basicConfig(level=logging.INFO, format="[INTER] %(message)s")
logger = logging.getLogger("inter_agent")


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inter-agent anomaly detection")
    parser.add_argument("--once", action="store_true", help="Single-shot detection")
    parser.add_argument("--simulate", action="store_true", help="Run with simulated data")
    args = parser.parse_args()

    if args.simulate:
        run_simulate()
    elif args.once:
        run_once()
    else:
        run_loop()
