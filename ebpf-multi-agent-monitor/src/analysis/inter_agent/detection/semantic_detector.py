import json
import logging
import base64
from typing import Optional
from collections import deque

logger = logging.getLogger(__name__)


class SemanticAnomalyDetector:
    """Detects semantic anomalies in inter-agent messages using Qwen API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:11434/v1",
        model_name: str = "qwen2.5:7b",
        window_size: int = 3,
        risk_threshold: float = 0.5,
        enabled: bool = True,
        timeout: int = 30,
        max_tokens: int = 1024,
    ):
        self._base_url = base_url.rstrip("/")
        self._model_name = model_name
        self._window_size = window_size
        self._risk_threshold = risk_threshold
        self._enabled = enabled
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._api_key = api_key or ""

        self._message_buffer: deque = deque(maxlen=window_size)
        self._topology: str = "unknown"
        self._task_context: str = "unknown"

    def detect(self, obs: dict) -> dict:
        if not self._enabled:
            return {"status": "disabled", "risk": 0.0, "anomalies": [],
                    "summary": "", "raw_response": None}

        current_msgs = self._format_messages(obs)
        self._message_buffer.append(current_msgs)

        if len(self._message_buffer) < 2:
            return {"status": "warming_up", "risk": 0.0, "anomalies": [],
                    "summary": "", "raw_response": None}

        topology = self._topology = self._infer_topology(obs)
        metrics = self._format_metrics(obs)

        task = self._extract_task_context(obs)
        if task:
            self._task_context = task

        buffer_lines = [
            f"--- Window {i+1} ---\n{msgs}"
            for i, msgs in enumerate(self._message_buffer)
        ]
        msg_history = "\n".join(buffer_lines)

        prompt = self._build_prompt(topology, self._task_context, metrics, msg_history)

        try:
            raw = self._call_qwen(prompt)
            result = self._parse_response(raw)
            result["status"] = "success"
            result["raw_response"] = raw
            return result
        except Exception as e:
            logger.warning("Semantic detection failed: %s", e)
            return {"status": "failed", "risk": 0.0, "anomalies": [],
                    "summary": f"API error: {e}", "raw_response": None}

    def _format_messages(self, obs: dict, name_map: dict = None) -> str:
        msgs = obs.get("messages", [])
        lines = []
        for m in msgs:
            src = m.get("src", "?")
            dst = m.get("dst", "?")
            tp = m.get("msg_type", "?")
            raw_data = m.get("data", "")
            content = ""
            if raw_data:
                try:
                    content = base64.b64decode(raw_data).decode("utf-8", errors="replace")
                except Exception:
                    content = "(base64 decode error)"
            content = content.strip()[:320]
            ts = m.get("timestamp_ns", 0)
            if content:
                lines.append(f"[{ts}] {src} -> {dst} [{tp}]: {content}")
            else:
                lines.append(f"[{ts}] {src} -> {dst} [{tp}]")
        return "\n".join(lines) if lines else "(no messages)"

    def _format_metrics(self, obs: dict) -> str:
        agents = obs.get("agents", {})
        lines = []
        keys = [
            "cpu_usage", "memory_usage", "api_call_count",
            "msg_sent", "msg_received",
            "proc_exec_count", "proc_fork_count",
            "fs_open_count", "fs_read_count", "fs_write_count", "fs_unlink_count",
            "net_connect_count", "net_send_count", "net_recv_count",
            "shell_exec_count", "sensitive_file_count", "unique_files_count",
        ]
        for aid, info in agents.items():
            vals = []
            for k in keys:
                v = info.get(k, 0)
                if isinstance(v, float):
                    vals.append(f"{k}={v:.2f}")
                else:
                    vals.append(f"{k}={v}")
            lines.append(f"  {aid}: " + " ".join(vals))
        return "\n".join(lines) if lines else "(no agents)"

    def _extract_task_context(self, obs: dict) -> str:
        for m in obs.get("messages", []):
            raw_data = m.get("data", "")
            if not raw_data:
                continue
            try:
                text = base64.b64decode(raw_data).decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if text and len(text) > 10 and m.get("msg_type") in ("assistant", "user"):
                return text[:200]
        return ""

    def _infer_topology(self, obs: dict) -> str:
        interactions = obs.get("interactions", [])
        if not interactions:
            return "unknown"
        agents = set(obs.get("agents", {}).keys())
        senders = set()
        for it in interactions:
            s = it.get("src", "")
            if s in agents:
                senders.add(s)
        # Check who sends messages
        msgs = obs.get("messages", [])
        msg_senders = set(m.get("src", "") for m in msgs if m.get("src", "") in agents)
        all_senders = senders | msg_senders
        # If only agent_0 sends (hierarchical with supervisor), else p2p
        if len(all_senders) <= 1:
            sorted_agents = sorted(agents)
            if sorted_agents and all_senders == {sorted_agents[0]}:
                return "hierarchical"
            return "hierarchical"
        return "peer-to-peer"

    def _build_prompt(self, topology: str, task: str, metrics: str,
                      msg_history: str) -> str:
        return (
            "You analyze multi-agent system observations. "
            "First describe what is happening, then detect anomalies.\n\n"
            "STEP 1: Summarize the task and each agent's role.\n"
            "STEP 2: Compare each agent's messages against its metrics.\n"
            "STEP 3: If all messages match metrics (agent does what it says): risk=0.0 NORMAL.\n"
            "STEP 4: If a message claims X but metrics show NOT X: classify anomaly.\n\n"
            "Anomaly classes:\n"
            "  stale_state, state_conflict, partial_visibility, message_disorder,\n"
            "  timeout_retry, ignore_input, reasoning_action_mismatch,\n"
            "  wrong_assumption, task_derailment, concealment, premature_convergence\n\n"
            "Risk: 0.0=normal, 0.6+=clear message-metric contradiction\n\n"
            f"Topology: {topology}  Task: {task}\n\n"
            f"Messages:\n{msg_history}\n\n"
            f"Metrics (per-agent):\n{metrics}\n\n"
            "Response format (JSON only):\n"
            '{"overall_risk": 0.0-1.0, "anomalies": [{"type": "<type>", '
            '"agents": ["<agent_id>", ...], "risk": 0.0-1.0, '
            '"evidence": "describe the contradiction"}], '
            '"summary": "one-line assessment"}'
        )

    def _call_qwen(self, prompt: str) -> str:
        import requests
        import time
        last_error = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    f"{self._base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self._model_name,
                        "messages": [
                            {"role": "system", "content": (
                                "You are a semantic anomaly detector for multi-agent "
                                "LLM systems. Output ONLY valid JSON."
                            )},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": self._max_tokens,
                    },
                    timeout=self._timeout,
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
                return content.strip()
            except Exception as e:
                last_error = e
                logger.warning("API attempt %d/3 failed: %s", attempt + 1, e)
                if attempt < 2:
                    time.sleep(5)
        raise last_error

    def _parse_response(self, raw: str) -> dict:
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1]
            raw = raw.rsplit("```", 1)[0]
        raw = raw.strip()
        # Remove leading newlines/whitespace before JSON
        start = raw.find("{")
        if start >= 0:
            raw = raw[start:]
        end = raw.rfind("}")
        if end >= 0:
            raw = raw[:end+1]
        if not raw:
            return {"risk": 0.0, "anomalies": [], "summary": "no_json_found"}
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Failed to parse semantic response as JSON: %.200s", raw)
            return {"risk": 0.0, "anomalies": [], "summary": "parse_failed"}
        if not isinstance(result.get("anomalies"), list):
            result["anomalies"] = []
        if not isinstance(result.get("overall_risk"), (int, float)):
            result["overall_risk"] = 0.0
        if not isinstance(result.get("summary"), str):
            result["summary"] = ""
        return {
            "risk": min(float(result.get("overall_risk", 0)), 1.0),
            "anomalies": result.get("anomalies", []),
            "summary": result.get("summary", ""),
        }

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def clear(self):
        self._message_buffer.clear()
        self._topology = "unknown"
        self._task_context = "unknown"
