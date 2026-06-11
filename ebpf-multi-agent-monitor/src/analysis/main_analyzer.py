#!/usr/bin/env python3
import sys
import time
import redis
import json
from audit_engine import AuditEngine
from intra_agent.main import IntraAgentAnalyzer
from inter_agent.main import InterAgentAnalyzer
from sqlite_store import SQLiteStore

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_CHANNEL = "ebpf_events"

class MainAnalyzer:
    def __init__(self):
        print("[ANALYZER] Initializing Main Analyzer...")
        self.redis_client = None
        self.pubsub = None
        self.anomaly_seq = 0
        self.audit_engine = AuditEngine()
        self.intra_analyzer = IntraAgentAnalyzer()
        self.inter_analyzer = InterAgentAnalyzer()
        self.sqlite_store = SQLiteStore()

        print("[ANALYZER] Main Analyzer initialized successfully")

    def connect_redis(self):
        print(f"[ANALYZER] Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}...")
        try:
            self.redis_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True
            )
            self.redis_client.ping()
            self.pubsub = self.redis_client.pubsub()
            self.pubsub.subscribe(REDIS_CHANNEL)
            print("[ANALYZER] Connected to Redis successfully")
            return True
        except Exception as e:
            print(f"[ANALYZER] Failed to connect to Redis: {e}")
            return False

    def _agent_id_for_pid(self, pid):
        return f"agent_{int(pid)}"

    def _push_anomaly(self, payload):
        self.anomaly_seq += 1
        record = {
            "anomaly_id": f"anom_{self.anomaly_seq:06d}",
            "rule": str(payload.get("rule", "UNKNOWN")),
            "severity": str(payload.get("severity", "LOW")),
            "timestamp_ns": int(payload.get("timestamp_ns", time.time_ns())),
            "pid": int(payload.get("pid", 0)),
            "tid": int(payload.get("tid", payload.get("pid", 0))),
            "comm": str(payload.get("comm", "unknown")),
            "agent_id": str(payload.get("agent_id", self._agent_id_for_pid(payload.get("pid", 0)))),
            "object": str(payload.get("object", "-")),
            "reason": str(payload.get("reason", payload.get("description", "-"))),
            "details": json.dumps(payload.get("details", {}), ensure_ascii=False),
        }
        if self.redis_client:
            try:
                self.redis_client.xadd("inter:anomalies", record)
            except Exception as e:
                print(f"[ANALYZER] Failed to push anomaly: {e}")
        self.sqlite_store.persist_anomaly(record)

    def _push_inter_alerts(self, alerts, event_data):
        for alert in alerts:
            payload = {
                "rule": alert.get("rule", "INTER_AGENT_ALERT"),
                "severity": alert.get("severity", "LOW"),
                "timestamp_ns": int(event_data.get("timestamp", time.time_ns())),
                "pid": int(alert.get("pid", event_data.get("pid", 0))),
                "tid": int(alert.get("pid", event_data.get("pid", 0))),
                "comm": event_data.get("comm", "unknown"),
                "agent_id": event_data.get(
                    "agent_id",
                    self._agent_id_for_pid(alert.get("pid", event_data.get("pid", 0))),
                ),
                "object": event_data.get("filename") or event_data.get("dip") or "-",
                "reason": alert.get("desc", "-"),
                "details": {
                    "source": "inter_agent",
                    "event_type": event_data.get("type", 0),
                },
            }
            self._push_anomaly(payload)

    def _push_intra_request(self, req):
        payload = {
            "rule": req.get("rule", "INTRA_AGENT_ALERT"),
            "severity": req.get("severity", "LOW"),
            "timestamp_ns": int(req.get("timestamp_ns", time.time_ns())),
            "pid": int(req.get("pid", 0)),
            "tid": int(req.get("tid", req.get("pid", 0))),
            "comm": req.get("comm", "unknown"),
            "agent_id": req.get("agent_id", self._agent_id_for_pid(req.get("pid", 0))),
            "object": req.get("object", "-"),
            "reason": req.get("reason", "-"),
            "details": {"source": "intra_agent"},
        }
        self._push_anomaly(payload)

    def process_sys_event(self, event_data):
        # 统一获取基础通用字段
        event_type = event_data.get('type', 'unknown')
        pid = event_data.get('pid', 0)
        uid = event_data.get('uid', 0)
        comm = event_data.get('comm', 'unknown')
        # 获取我们刚在 C 语言加上的核心字段 timestamp
        timestamp = event_data.get('timestamp', 0) 

        print(f"[ANALYZER] Processing SYS_EVENT | Type: {event_type} | PID: {pid} | UID: {uid} | Comm: {comm}")
        print(f"[ANALYZER]   -> Timestamp: {timestamp} ns")

        # 动态处理不同事件的特有字段
        if 'filename' in event_data and event_data['filename']:
            print(f"[ANALYZER]   -> Target File: {event_data['filename']}")
            
        if 'dip' in event_data and 'dport' in event_data:
            print(f"[ANALYZER]   -> Network Target: {event_data['dip']}:{event_data['dport']}")

        # 路由 1: 交给 Inter-Agent
        inter_alerts = self.inter_analyzer.run_analysis(event_data)
        if inter_alerts:
            print(f"[ANALYZER-INTER] 发现跨进程/关联异常: {inter_alerts}")
            self._push_inter_alerts(inter_alerts, event_data)

        # 路由 2: 交给 Intra-Agent
        intra_reqs = self.intra_analyzer.analyze_event(event_data)
        if not intra_reqs:
            return []

        # 路由 3: 送入审计引擎
        results = []
        for req in intra_reqs:
            self._push_intra_request(req)
            result = self.audit_engine.audit_intra_request(req)
            self.sqlite_store.persist_audit_result(req, result)
            print(f"[ANALYZER-AUDIT] 单体审计结果: {result}")
            results.append(result)
        return results

    def process_ssl_event(self, event_data):
        print(f"[ANALYZER] Processing SSL event: {event_data}")
        event_type = event_data.get('type', 'unknown')
        pid = event_data.get('pid', 0)
        comm = event_data.get('comm', 'unknown')
        data_len = event_data.get('data_len', 0)

        print(f"[ANALYZER]   Event type: {event_type}, PID: {pid}, Comm: {comm}, Data length: {data_len}")

        inter_alerts = self.inter_analyzer.run_analysis(event_data)
        if inter_alerts:
            print(f"[ANALYZER-INTER] 发现跨进程/关联异常: {inter_alerts}")
            self._push_inter_alerts(inter_alerts, event_data)

        # SSL 流量目前主要属于单体行为分析的范畴
        intra_reqs = self.intra_analyzer.analyze_event(event_data)
        if not intra_reqs:
            print("[ANALYZER]   无单体审计请求")
            return []

        results = []
        for req in intra_reqs:
            self._push_intra_request(req)
            result = self.audit_engine.audit_intra_request(req)
            self.sqlite_store.persist_audit_result(req, result)
            print(f"[ANALYZER-AUDIT] SSL单体审计结果: {result}")
            results.append(result)
        return results

    def run(self):
        print("[ANALYZER] Starting Main Analyzer...")
        print("[ANALYZER] Waiting for events from Redis channel...")

        if not self.connect_redis():
            print("[ANALYZER] Cannot proceed without Redis connection")
            return

        print("[ANALYZER] Listening for events on channel:", REDIS_CHANNEL)

        try:
            while True:
                message = self.pubsub.get_message(timeout=1.0)
                if message and message['type'] == 'message':
                    event_data = json.loads(message['data'])
                    self.sqlite_store.persist_event(event_data)
                    print(f"[ANALYZER] Received event: {event_data}")

                    event_type = event_data.get('type', 0)
                    if event_type in [1, 2, 3, 4, 5]:
                        self.process_sys_event(event_data)
                    elif event_type in [6, 7]:
                        self.process_ssl_event(event_data)
                    else:
                        print(f"[ANALYZER] Unknown event type: {event_type}")

                time.sleep(0.1)

        except KeyboardInterrupt:
            print("\n[ANALYZER] Received keyboard interrupt, shutting down...")
        except Exception as e:
            print(f"[ANALYZER] Error: {e}")
        finally:
            if self.pubsub:
                self.pubsub.unsubscribe()
                self.pubsub.close()
            if self.redis_client:
                self.redis_client.close()
            self.sqlite_store.close()
            print("[ANALYZER] Main Analyzer shutdown complete")


if __name__ == "__main__":
    print("=" * 60)
    print("[ANALYZER] eBPF Multi-Agent Monitor - Main Analyzer")
    print("=" * 60)

    analyzer = MainAnalyzer()
    analyzer.run()
