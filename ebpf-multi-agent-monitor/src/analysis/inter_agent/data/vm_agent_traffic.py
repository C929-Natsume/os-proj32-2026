"""Generate inter-agent Ollama traffic for eBPF capture.

Spawns multiple processes that make HTTP POST requests to Ollama,
simulating multi-agent conversations. The eBPF ringbuf_handler captures
these sendmsg/recvmsg syscalls as inter-agent messages with data payloads.

Usage:
    python vm_agent_traffic.py --rounds 5 --agents 3 --delay 3
"""
import argparse
import json
import logging
import multiprocessing
import os
import time
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(processName)s] %(message)s")
logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"

AGENT_PROMPTS = {
    "planner": "You are a planner agent. Briefly describe how you would organize a team project. Keep it under 50 words.",
    "coder": "You are a coder agent. Briefly explain what a hash table is. Keep it under 50 words.",
    "reviewer": "You are a reviewer agent. Briefly list three code review best practices. Keep it under 50 words.",
    "analyst": "You are an analyst agent. Briefly describe the benefits of monitoring systems. Keep it under 50 words.",
    "writer": "You are a writer agent. Briefly explain what technical debt is. Keep it under 50 words.",
}

PROMPT_NAMES = list(AGENT_PROMPTS.keys())


def _ollama_chat(prompt: str) -> str:
    """Call Ollama API and return response text."""
    payload = json.dumps({
        "model": "llama3",
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": 100},
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data.get("response", "")[:200]
    except Exception as e:
        logger.warning("Ollama call failed: %s", e)
        return ""


def _agent_worker(agent_id: str, rounds: int, delay: float):
    """Worker process that makes Ollama calls."""
    proc_name = multiprocessing.current_process().name
    logger.info("Agent %s started (pid=%d)", agent_id, os.getpid())

    for r in range(rounds):
        prompt_idx = (hash(agent_id) + r) % len(PROMPT_NAMES)
        prompt_name = PROMPT_NAMES[prompt_idx]
        prompt = AGENT_PROMPTS[prompt_name]
        logger.info("[%s round %d/%d] calling Ollama with '%s' prompt",
                    agent_id, r + 1, rounds, prompt_name)

        response = _ollama_chat(prompt)
        logger.info("[%s] received %d chars from Ollama",
                    agent_id, len(response))

        time.sleep(delay * (0.5 + (hash(agent_id + str(r)) % 100) / 100.0))

    logger.info("Agent %s done", agent_id)


def main():
    parser = argparse.ArgumentParser(description="Generate inter-agent traffic")
    parser.add_argument("--rounds", type=int, default=4,
                        help="Number of conversation rounds per agent")
    parser.add_argument("--agents", type=int, default=3,
                        help="Number of agent processes")
    parser.add_argument("--delay", type=float, default=5.0,
                        help="Delay (seconds) between Ollama calls")
    args = parser.parse_args()

    agent_names = [f"Agent{chr(65 + i)}" for i in range(args.agents)]
    logger.info("Starting %d agents, %d rounds each, %.1fs delay",
                args.agents, args.rounds, args.delay)

    processes = []
    for name in agent_names:
        p = multiprocessing.Process(
            target=_agent_worker,
            args=(name, args.rounds, args.delay),
            name=name,
        )
        p.start()
        processes.append(p)
        time.sleep(1)

    for p in processes:
        p.join()

    logger.info("All agents done")


if __name__ == "__main__":
    main()
