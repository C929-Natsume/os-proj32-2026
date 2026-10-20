#!/usr/bin/env python3
import json
import os
import sqlite3
import threading
import time

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


class SQLiteStore:
    def __init__(self):
        self.enabled = True
        self.db_path = self._default_db_path()
        self._conn = None
        self._lock = threading.Lock()
        self._load_config()
        if self.enabled:
            self._init_db()

    @staticmethod
    def _config_path():
        return os.path.join(os.path.dirname(__file__), "../config/app_config.yaml")

    @staticmethod
    def _default_db_path():
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        return os.path.join(root, "logs", "alerts", "analysis.db")

    def _load_config(self):
        cfg_path = self._config_path()
        if not yaml or not os.path.exists(cfg_path):
            return
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            storage_cfg = cfg.get("storage") or {}
            sqlite_cfg = storage_cfg.get("sqlite") or {}
            self.enabled = bool(sqlite_cfg.get("enabled", True))
            path = str(sqlite_cfg.get("path", self.db_path) or self.db_path).strip()
            if path:
                if os.path.isabs(path):
                    self.db_path = path
                else:
                    base_dir = os.path.dirname(cfg_path)
                    self.db_path = os.path.abspath(os.path.join(base_dir, path))
        except Exception as e:
            print(f"[SQLITE] Failed to read config, using default path: {e}")

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ns INTEGER NOT NULL,
                event_type INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                ppid INTEGER,
                uid INTEGER,
                comm TEXT,
                agent_id TEXT,
                main_pid INTEGER,
                object TEXT,
                payload_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                anomaly_id TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                tid INTEGER,
                comm TEXT,
                agent_id TEXT,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                object TEXT,
                reason TEXT,
                details_json TEXT,
                created_at_ns INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ns INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                tid INTEGER,
                comm TEXT,
                agent_id TEXT,
                rule TEXT,
                severity TEXT,
                request_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_anomalies_agent ON anomalies(agent_id);
            CREATE INDEX IF NOT EXISTS idx_audit_results_timestamp ON audit_results(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_audit_results_agent ON audit_results(agent_id);
            """
        )
        self._conn.commit()
        print(f"[SQLITE] SQLite persistence ready: {self.db_path}")

    @staticmethod
    def _json_dump(payload):
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)

    def persist_event(self, event_data):
        if not self.enabled or not self._conn:
            return
        obj = event_data.get("filename") or event_data.get("dip") or "-"
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO events (
                    timestamp_ns, event_type, pid, ppid, uid, comm, agent_id,
                    main_pid, object, payload_json, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(event_data.get("timestamp", time.time_ns())),
                    int(event_data.get("type", 0)),
                    int(event_data.get("pid", 0)),
                    int(event_data.get("ppid", 0)),
                    int(event_data.get("uid", 0)),
                    str(event_data.get("comm", "unknown")),
                    str(event_data.get("agent_id", "")),
                    int(event_data.get("main_pid", 0)),
                    str(obj),
                    self._json_dump(event_data),
                    time.time_ns(),
                ),
            )
            self._conn.commit()

    def persist_anomaly(self, record):
        if not self.enabled or not self._conn:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO anomalies (
                    anomaly_id, timestamp_ns, pid, tid, comm, agent_id, rule,
                    severity, object, reason, details_json, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.get("anomaly_id", "")),
                    int(record.get("timestamp_ns", time.time_ns())),
                    int(record.get("pid", 0)),
                    int(record.get("tid", 0)),
                    str(record.get("comm", "unknown")),
                    str(record.get("agent_id", "")),
                    str(record.get("rule", "UNKNOWN")),
                    str(record.get("severity", "LOW")),
                    str(record.get("object", "-")),
                    str(record.get("reason", "-")),
                    str(record.get("details", "{}")),
                    time.time_ns(),
                ),
            )
            self._conn.commit()

    def persist_audit_result(self, req, result):
        if not self.enabled or not self._conn:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_results (
                    timestamp_ns, pid, tid, comm, agent_id, rule, severity,
                    request_json, result_json, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(req.get("timestamp_ns", time.time_ns())),
                    int(req.get("pid", 0)),
                    int(req.get("tid", req.get("pid", 0))),
                    str(req.get("comm", "unknown")),
                    str(req.get("agent_id", f"agent_{int(req.get('pid', 0))}")),
                    str(req.get("rule", "")),
                    str(req.get("severity", "LOW")),
                    self._json_dump(req),
                    self._json_dump(result),
                    time.time_ns(),
                ),
            )
            self._conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
