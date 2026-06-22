"""Test DeepSeek API connectivity and LLM escalation flow.

Usage:
    python test_deepseek_api.py                     # uses DEEPSEEK_API_KEY env var or prompts
    python test_deepseek_api.py --key sk-xxxxx      # pass key directly
    python test_deepseek_api.py --no-llm            # test pipeline without LLM
"""

import json, os, sys, argparse
from pathlib import Path

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)  # inter_agent/tests/ -> project root
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, str(Path(PROJECT_ROOT) / "inter_agent"))


def test_api_connectivity(api_key: str) -> dict:
    """Test basic DeepSeek API connectivity with a simple prompt."""
    import requests
    resp = requests.post(
        "https://api.deepseek.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant. Respond concisely."},
                {"role": "user", "content": "Say hello in one short sentence."},
            ],
            "temperature": 0.0,
            "max_tokens": 50,
        },
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    print(f"  Response: {content}")
    print(f"  Model: {data['model']}, Usage: {data.get('usage', {})}")
    return data


def test_anomaly_escalation(api_key: str) -> dict:
    """Simulate a real anomaly escalation call to DeepSeek."""
    import requests
    context = {
        "timestamp_ns": 1717000000000000000,
        "agents": {
            "agent_0": {"risk_score": 0.12, "gnn_score": 0.08, "cls_probability": 0.05},
            "agent_1": {"risk_score": 0.15, "gnn_score": 0.10, "cls_probability": 0.07},
            "agent_2": {"risk_score": 0.92, "gnn_score": 0.88, "cls_probability": 0.95},
            "agent_3": {"risk_score": 0.10, "gnn_score": 0.06, "cls_probability": 0.04},
        },
        "anomalous_agents": ["agent_2"],
        "source_agent": "agent_2",
        "graph_score": 0.87,
        "recon_error": 1.42,
        "propagation_paths": [],
        "data_summary": {"agent_count": 4, "edge_count": 12, "mean_risk": 0.28, "max_risk": 0.92},
    }
    agents_str = "\n".join(
        f"  {aid}: risk={info['risk_score']}, gnn_score={info['gnn_score']}, cls_prob={info['cls_probability']}"
        for aid, info in sorted(context["agents"].items())
    )
    prompt = (
        f"Multi-agent system anomaly detected.\n\n"
        f"Graph anomaly score: {context['graph_score']}\n"
        f"Reconstruction error: {context['recon_error']}\n"
        f"Anomalous agents: {context['anomalous_agents']}\n"
        f"Source agent: {context['source_agent']}\n"
        f"Propagation paths: {context['propagation_paths']}\n"
        f"Data summary: {json.dumps(context['data_summary'])}\n\n"
        f"Per-agent details:\n{agents_str}\n\n"
        "Determine if this is a genuine threat and recommend action. "
        "Respond in JSON only with keys: is_threat (bool), severity (LOW/MEDIUM/HIGH/CRITICAL), "
        "reasoning (str), recommended_action (str)."
    )
    resp = requests.post(
        "https://api.deepseek.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a security analyst evaluating multi-agent system anomalies. Respond in JSON format."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 512,
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    print(f"  Raw response:\n{content}\n")
    try:
        cleaned = content.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[len("```json"):]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-len("```")]
        cleaned = cleaned.strip()
        verdict = json.loads(cleaned)
    except json.JSONDecodeError:
        verdict = {"raw": content}
    print(f"  Parsed verdict: {json.dumps(verdict, indent=2, ensure_ascii=False)}")
    return data


def run_pipeline_without_llm():
    """Run the detection pipeline using the Simulator + MonitorAgent (no LLM key needed)."""
    from inter_agent.monitor.agent import MonitorAgent
    from inter_agent.data.simulator import Simulator
    from inter_agent.config import load_config

    config = load_config()
    config["llm"]["enabled"] = False

    model_path = Path(PROJECT_ROOT) / "inter_agent" / "models" / "anomaly_detector.pth"
    gnn_model_path = Path(PROJECT_ROOT) / "inter_agent" / "models" / "gnn_model.pth"
    if model_path.exists():
        config["model"]["model_path"] = str(model_path)
        print(f"  Using pre-trained model: {model_path}")
    else:
        print("  No pre-trained model found, running rule-only")

    agent = MonitorAgent(config=config)

    sim = Simulator(num_agents=4, seed=42)

    print("Generating normal observations...")
    obs_normal = sim.generate_normal()
    agent_ids = list(obs_normal["agents"].keys())
    print(f"  Agents: {agent_ids}")
    print(f"  Interactions: {len(obs_normal['interactions'])}")
    print(f"  Messages: {len(obs_normal['messages'])}")

    print("Running detection on normal data...")
    report_normal = agent.process_observation(obs_normal)
    print(f"  Response level: {report_normal.response_level.value}")
    print(f"  Max risk: {report_normal.max_risk:.4f}")
    print(f"  Anomaly nodes: {report_normal.anomalous_nodes}")

    print("Injecting resource anomaly into agent_2...")
    sim.inject_resource_anomaly(obs_normal, "agent_2")
    obs_normal["agents"]["agent_2"]["cpu_usage"] = 0.95
    obs_normal["agents"]["agent_2"]["memory_usage"] = 0.92

    print("Running detection on anomalous data...")
    report_anom = agent.process_observation(obs_normal)
    print(f"  Response level: {report_anom.response_level.value}")
    print(f"  Max risk: {report_anom.max_risk:.4f}")
    print(f"  Anomaly nodes: {report_anom.anomalous_nodes}")

    verdict = "PASS" if len(report_anom.anomalous_nodes) > 0 else "FAIL (no anomaly detected)"
    print(f"\n  Verdict: {verdict}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test DeepSeek API and anomaly pipeline")
    parser.add_argument("--key", help="DeepSeek API key (or set DEEPSEEK_API_KEY env var)")
    parser.add_argument("--no-llm", action="store_true", help="Test pipeline without LLM")
    args = parser.parse_args()

    api_key = args.key or os.environ.get("DEEPSEEK_API_KEY", "")

    print("=" * 60)
    print("DeepSeek API & Pipeline Test")
    print("=" * 60)

    if args.no_llm:
        print("\n[Pipeline Test] (no LLM)...")
        run_pipeline_without_llm()
        sys.exit(0)

    if not api_key:
        api_key = input("Enter DeepSeek API key (or press Enter to skip LLM tests): ").strip()

    if api_key:
        print("\n[Test 1] Basic API Connectivity...")
        test_api_connectivity(api_key)

        print("\n[Test 2] Anomaly Escalation...")
        test_anomaly_escalation(api_key)
    else:
        print("\n[Skip] No API key, running pipeline-only test...")
        run_pipeline_without_llm()

    print("\nDone.")
