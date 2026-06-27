#!/usr/bin/env python3
import json
import os
import time
from pathlib import Path


class IntraUserLogger:
    def __init__(self, log_dir=None):
        base_dir = Path(__file__).resolve().parents[3]
        self.log_dir = Path(log_dir or (base_dir / "logs" / "intra_agent"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"anomaly_{time.strftime('%Y%m%d_%H%M%S')}.log"

    def log_audit(self, req, result, semantic_context=None):
        block = self._format_block(req, result, semantic_context or {})
        print(block, flush=True)
        with self.log_path.open("a", encoding="utf-8") as fp:
            fp.write(block + "\n")

    def _format_block(self, req, result, semantic_context):
        llm_review = result.get("llm_review") or {}
        event_lines = self._build_event_sequence(req, semantic_context)
        semantic_lines = self._build_semantic_section(semantic_context)
        root_cause = self._build_root_cause(req, result, llm_review)
        summary = self._build_summary(result, llm_review)
        ts_ns = int(req.get("timestamp_ns", 0) or 0)
        ts_text = self._format_ts(ts_ns)
        risk = llm_review.get("risk_level", req.get("severity", "LOW"))
        agent_id = req.get("agent_id") or f"agent_{int(req.get('pid', 0) or 0)}"
        object_text = req.get("object", "-")
        lines = [
            "=" * 54,
            f"[solo] {req.get('rule', 'UNKNOWN')} ({risk})",
            f"time={ts_text}  pid={req.get('pid', 0)}  tid={req.get('tid', req.get('pid', 0))}",
            f"agent={agent_id}  comm={req.get('comm', 'unknown')}  object={object_text}",
            "-" * 54,
            "[event sequence]",
            *event_lines,
            "[semantic association]",
            *semantic_lines,
            "[root cause]",
            f"  {root_cause}",
            "[analysis report]",
            f"  {summary}",
        ]
        if llm_review:
            evidence = llm_review.get("evidence") or []
            if evidence:
                lines.append("[evidence]")
                lines.extend([f"  - {item}" for item in evidence[:5]])
        lines.append("=" * 54)
        return "\n".join(lines)

    def _build_event_sequence(self, req, semantic_context):
        seq = []
        req_id = req.get("req_id", "-")
        seq.append(
            f"  - req#{req_id}  rule={req.get('rule', 'UNKNOWN')}  severity={req.get('severity', 'LOW')}"
        )
        seq.append(f"  - object={req.get('object', '-')}  reason={req.get('reason', '-')}")
        for msg in (semantic_context.get("messages") or [])[-3:]:
            seq.append(
                f"  - {msg.get('type', 'message')}  ts={self._format_ts(msg.get('timestamp_ns', 0))}  "
                f"preview={self._shorten(msg.get('preview', ''))}"
            )
        return seq

    def _build_semantic_section(self, semantic_context):
        messages = semantic_context.get("messages") or []
        if not messages:
            return ["  prompt/response: 未命中最近语义上下文"]
        latest = messages[-1]
        return [
            f"  agent={semantic_context.get('agent_id', '-')}",
            f"  {latest.get('type', 'message')}: {self._shorten(latest.get('preview', ''))}",
        ]

    def _build_root_cause(self, req, result, llm_review):
        if llm_review.get("reasoning"):
            return self._shorten(llm_review["reasoning"], 220)
        return self._shorten(result.get("reason", req.get("reason", "-")), 220)

    def _build_summary(self, result, llm_review):
        if llm_review.get("summary"):
            return self._shorten(llm_review["summary"], 220)
        return self._shorten(
            f"decision={result.get('decision', '-')} status={result.get('status', '-')}",
            220,
        )

    def _format_ts(self, ts_ns):
        if not ts_ns:
            return "-"
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_ns / 1_000_000_000))
        except Exception:
            return str(ts_ns)

    def _shorten(self, text, limit=120):
        value = (text or "").replace("\n", " ").replace("\r", " ").strip()
        if len(value) <= limit:
            return value
        return value[: limit - 3] + "..."
