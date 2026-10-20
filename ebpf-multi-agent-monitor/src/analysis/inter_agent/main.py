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
