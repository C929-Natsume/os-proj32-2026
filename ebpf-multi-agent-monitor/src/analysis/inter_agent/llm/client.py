import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class LLMEscalator:
    """DeepSeek LLM client for anomaly escalation.

    When GNN anomaly scores exceed the threshold, this client
    formats the anomaly context and calls DeepSeek API for
    higher-level assessment.

    Set DEEPSEEK_API_KEY env var or pass api_key directly.
    Disabled by default; enable via config llm.enabled=True.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com/v1",
        enabled: bool = False,
    ):
        self._model_name = model_name
        self._base_url = base_url.rstrip("/")
        self._enabled = enabled
        self._api_key = api_key

        if not self._api_key:
            import os
            self._api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if not self._api_key and enabled:
            logger.warning("LLMEscalator enabled but no API key set")

    @property
    def is_enabled(self) -> bool:
        return self._enabled and bool(self._api_key)

    def evaluate(self, context: dict) -> Optional[dict]:
        """Send anomaly context to DeepSeek and return verdict.

        context format (built by MonitorAgent._build_escalation_context):
        {
            "timestamp_ns": int,
            "agents": { agent_id: {"risk_score": float, "gnn_score": float, ...} },
            "anomalous_agents": [str],
            "source_agent": str | None,
            "graph_score": float,
            "recon_error": float,
            "propagation_paths": [...],
            "data_summary": {...}
        }
        """
        if not self.is_enabled:
            return None

        prompt = self._build_prompt(context)
        try:
            import requests
            resp = requests.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model_name,
                    "messages": [
                        {"role": "system", "content": "You are a security analyst evaluating multi-agent system anomalies. Respond in JSON format with keys: is_threat (bool), severity (LOW/MEDIUM/HIGH/CRITICAL), reasoning (str), recommended_action (str)."},
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
            verdict = self._parse_verdict(content)
            logger.info("LLM verdict: %s", verdict)
            return verdict
        except Exception as e:
            logger.warning("LLM escalation failed: %s", e)
            return {
                "is_threat": True,
                "severity": "MEDIUM",
                "reasoning": f"LLM call failed ({e}); falling back to GNN score",
                "recommended_action": "isolate_agent",
            }

    def _build_prompt(self, context: dict) -> str:
        agents_str = "\n".join(
            f"  {aid}: risk={info['risk_score']}, "
            f"gnn_score={info['gnn_score']}, "
            f"cls_prob={info['cls_probability']}"
            for aid, info in sorted(context.get("agents", {}).items())
        )
        return (
            f"Multi-agent system anomaly detected.\n\n"
            f"Graph anomaly score: {context.get('graph_score', 0)}\n"
            f"Reconstruction error: {context.get('recon_error', 0)}\n"
            f"Anomalous agents: {context.get('anomalous_agents', [])}\n"
            f"Source agent: {context.get('source_agent', 'unknown')}\n"
            f"Propagation paths: {context.get('propagation_paths', [])}\n"
            f"Data summary: {json.dumps(context.get('data_summary', {}))}\n\n"
            f"Per-agent details:\n{agents_str}\n\n"
            "Determine if this is a genuine threat and recommend action. "
            "Respond in JSON only."
        )

    def _parse_verdict(self, content: str) -> dict:
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
            content = content.rsplit("```", 1)[0]
        content = content.strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {
                "is_threat": True,
                "severity": "MEDIUM",
                "reasoning": content[:200],
                "recommended_action": "isolate_agent",
            }
