from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from .config import MONITOR_ROOT, SQLITE_PATH
from .db import get_conn, parse_json, row_to_dict


def _load_llm_config() -> dict[str, Any]:
    cfg_path = MONITOR_ROOT / "src" / "config" / "app_config.yaml"
    if not cfg_path.exists():
        return {}
    try:
        with cfg_path.open("r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("llm") or {}
    except Exception:
        return {}


def _reference_models(active_model: str) -> list[dict[str, Any]]:
    candidates = [
        (active_model or "deepseek-chat", "active"),
        ("qwen-plus", "reference"),
        ("gpt-4o-mini", "reference"),
    ]
    seen: set[str] = set()
    items: list[dict[str, Any]] = []
    for model_id, status in candidates:
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        items.append(
            {
                "id": model_id,
                "label": model_id.replace("-", " ").title(),
                "status": status,
            }
        )
    return items


def _fetch_all(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [row_to_dict(row) for row in rows]


def get_health() -> dict[str, Any]:
    with get_conn() as conn:
        counts = {
            "events": conn.execute("select count(*) from events").fetchone()[0],
            "anomalies": conn.execute("select count(*) from anomalies").fetchone()[0],
            "audit_results": conn.execute("select count(*) from audit_results").fetchone()[0],
        }
    llm_cfg = _load_llm_config()
    return {
        "status": "ok",
        "monitor_root": str(MONITOR_ROOT),
        "sqlite_path": str(SQLITE_PATH),
        "llm": {
            "enabled": bool(llm_cfg.get("enabled", False)),
            "model": llm_cfg.get("model", "deepseek-chat"),
            "endpoint": llm_cfg.get("endpoint", ""),
        },
        "counts": counts,
    }


def get_models() -> list[dict[str, Any]]:
    llm_cfg = _load_llm_config()
    return _reference_models(str(llm_cfg.get("model", "deepseek-chat") or "deepseek-chat"))


def get_events(limit: int = 50) -> list[dict[str, Any]]:
    rows = _fetch_all(
        """
        select id, timestamp_ns, event_type, pid, ppid, uid, comm, agent_id, main_pid, object, payload_json
        from events
        order by id desc
        limit ?
        """,
        (limit,),
    )
    for row in rows:
        row["payload"] = parse_json(row.pop("payload_json", None))
    return rows


def get_anomalies(limit: int = 50) -> list[dict[str, Any]]:
    rows = _fetch_all(
        """
        select id, anomaly_id, timestamp_ns, pid, tid, comm, agent_id, rule, severity, object, reason, details_json
        from anomalies
        order by id desc
        limit ?
        """,
        (limit,),
    )
    for row in rows:
        row["details"] = parse_json(row.pop("details_json", None))
    return rows


def get_audit_results(limit: int = 50) -> list[dict[str, Any]]:
    rows = _fetch_all(
        """
        select id, timestamp_ns, pid, tid, comm, agent_id, rule, severity, request_json, result_json, created_at_ns
        from audit_results
        order by id desc
        limit ?
        """,
        (limit,),
    )
    for row in rows:
        row["request"] = parse_json(row.pop("request_json", None))
        row["result"] = parse_json(row.pop("result_json", None))
    return rows


def get_overview() -> dict[str, Any]:
    events = get_events(limit=200)
    anomalies = get_anomalies(limit=200)
    audits = get_audit_results(limit=200)

    severity_counter = Counter(item.get("severity", "UNKNOWN") for item in anomalies)
    rule_counter = Counter(item.get("rule", "UNKNOWN") for item in anomalies)
    agent_counter = Counter(item.get("agent_id") or item.get("comm") or "unknown" for item in events)

    return {
        "metrics": {
            "events": len(events),
            "anomalies": len(anomalies),
            "audit_results": len(audits),
            "agents_observed": len(agent_counter),
        },
        "severity_breakdown": dict(severity_counter),
        "top_rules": [
            {"rule": rule, "count": count}
            for rule, count in rule_counter.most_common(8)
        ],
        "top_agents": [
            {"agent": agent, "count": count}
            for agent, count in agent_counter.most_common(8)
        ],
    }
