#!/usr/bin/env python3
import sys
import time
import os
import re
import base64
import redis
import json
from audit_engine import AuditEngine
from intra_agent.main import IntraAgentAnalyzer
from inter_agent.main import InterAgentAnalyzer
from sqlite_store import SQLiteStore
from protocol_fingerprint import (
    fingerprint_protocol, parse_mcp_frames, extract_mcp_fields,
    parse_sse_events, extract_a2a_task_id, extract_a2a_agent_card,
    parse_acp_multipart, extract_acp_headers,
    extract_anp_graph, extract_anp_dids,
    split_http_message, has_http_headers,
)

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_CHANNEL = "ebpf_events"
MESSAGE_STREAM = "inter:messages"

EVENT_EXECVE = 1
EVENT_FORK = 2
EVENT_OPEN = 3
EVENT_UNLINK = 4
EVENT_CONNECT = 5
EVENT_SSL_READ = 6
EVENT_SSL_WRITE = 7
EVENT_CHMOD = 8
EVENT_AGENT_COMM = 9
EVENT_STDIO_READ = 10
EVENT_STDIO_WRITE = 11
EVENT_TCP_SEND = 12
EVENT_TCP_RECV = 13

SYS_EVENT_TYPES = {1, 2, 3, 4, 5, 8, 9}
RAW_PROTO_EVENT_TYPES = {10, 11, 12, 13}


class MainAnalyzer:
    def __init__(self):
        print("[ANALYZER] Initializing Main Analyzer...")
        self.redis_client = None
        self.redis_stream_client = None
        self.pubsub = None
        self.replay_history = os.environ.get("ANALYZER_REPLAY_HISTORY", "").lower() in {"1", "true", "yes"}
        self.verbose_events = os.environ.get("ANALYZER_VERBOSE_EVENTS", "").lower() in {"1", "true", "yes"}
        self.log_ssl_events = self.verbose_events or os.environ.get("ANALYZER_LOG_SSL_EVENTS", "").lower() in {"1", "true", "yes"}
        self.process_ssl_pubsub = os.environ.get("ANALYZER_PROCESS_SSL_PUBSUB", "").lower() in {"1", "true", "yes"}
        self.message_stream_last_id = "$"
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
                decode_responses=False
            )
            self.redis_client.ping()
            self.redis_stream_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=False
            )
            self.redis_stream_client.ping()
            self._initialize_stream_cursor()
            self.pubsub = self.redis_client.pubsub()
            self.pubsub.subscribe(REDIS_CHANNEL)
            print("[ANALYZER] Connected to Redis successfully")
            return True
        except Exception as e:
            print(f"[ANALYZER] Failed to connect to Redis: {e}")
            return False

    def _initialize_stream_cursor(self):
        if not self.redis_stream_client:
            return
        if self.replay_history:
            self.message_stream_last_id = "0-0"
            print(f"[ANALYZER] Stream replay enabled, reading {MESSAGE_STREAM} from beginning")
            return
        self.message_stream_last_id = "$"
        print(f"[ANALYZER] Stream replay disabled, following only new entries from {MESSAGE_STREAM}")

    def _agent_id_for_pid(self, pid):
        return f"agent_{int(pid)}"

    def _pid_from_agent_id(self, agent_id):
        if not agent_id:
            return 0
        try:
            text = str(agent_id)
            if text.startswith("agent_"):
                return int(text.split("_", 1)[1])
        except (TypeError, ValueError):
            return 0
        return 0

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

    def _short_preview(self, text, limit=120):
        text = (text or "").replace("\r", "\\r").replace("\n", "\\n")
        if len(text) > limit:
            return text[:limit] + "..."
        return text

    def _is_chunk_marker(self, text):
        return bool(re.fullmatch(r"[0-9a-fA-F]{1,8}", (text or "").strip()))

    def _looks_binary_payload(self, text):
        if not text:
            return False
        if any(marker in text for marker in ("HTTP/", "GET ", "POST ", "event:", "data:")):
            return False
        sample = text[:512]
        replacement_count = sample.count("\ufffd")
        printable_count = sum(1 for ch in sample if ch.isprintable() or ch in "\r\n\t")
        noisy_count = len(sample) - printable_count + replacement_count
        return noisy_count / max(len(sample), 1) > 0.25

    def _should_process_ssl_event(self, event_data):
        data = event_data.get("data", "") or ""
        if self._is_chunk_marker(data):
            return False
        if self._looks_binary_payload(data):
            return False
        return True

    def _log_event_summary(self, source, event_data):
        if self.verbose_events:
            print(f"[ANALYZER] Received {source}: {event_data}")
            return
        preview = self._short_preview(event_data.get("data", ""))
        print(
            "[ANALYZER] Received "
            f"{source}: type={event_data.get('type')} "
            f"pid={event_data.get('pid')} "
            f"comm={event_data.get('comm')} "
            f"len={event_data.get('data_len', 0)} "
            f"agent={event_data.get('agent_id', '-')} "
            f"preview={preview}"
        )

    def _coerce_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _safe_decode(self, value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if value is None:
            return ""
        return str(value)

    def _field_lookup(self, fields, key, default=""):
        if not fields:
            return default
        if key in fields:
            return fields.get(key, default)
        key_bytes = key.encode("utf-8")
        if key_bytes in fields:
            return fields.get(key_bytes, default)
        return default

    def _normalize_stream_event(self, stream_id, fields):
        if not fields:
            return None

        protocol = self._safe_decode(self._field_lookup(fields, "protocol", ""))
        msg_type = self._safe_decode(self._field_lookup(fields, "type", ""))
        if protocol == "ssl" or msg_type in {"prompt", "response"}:
            return self._normalize_stream_ssl_event(stream_id, fields)
        if protocol in {"stdio", "tcp"} or msg_type in {"send", "recv"}:
            return self._normalize_stream_raw_event(stream_id, fields)
        return None

    def _normalize_stream_ssl_event(self, stream_id, fields):
        if not fields:
            return None

        protocol = self._safe_decode(self._field_lookup(fields, "protocol", ""))
        msg_type = self._safe_decode(self._field_lookup(fields, "type", ""))
        if protocol != "ssl" and msg_type not in {"prompt", "response"}:
            return None

        data = self._safe_decode(self._field_lookup(fields, "data", ""))
        event_type = 7 if msg_type == "prompt" else 6
        agent_id = self._safe_decode(
            self._field_lookup(fields, "agent_id", self._field_lookup(fields, "src", ""))
        )
        pid = self._coerce_int(self._field_lookup(fields, "pid"), 0)
        if pid == 0:
            pid = self._coerce_int(self._field_lookup(fields, "src_pid"), 0)
        if pid == 0:
            pid = self._pid_from_agent_id(agent_id)

        main_pid = self._coerce_int(self._field_lookup(fields, "main_pid"), 0)
        if main_pid == 0:
            main_pid = pid

        comm = self._safe_decode(
            self._field_lookup(fields, "comm", self._field_lookup(fields, "src", "ssl"))
        )
        if comm.startswith("agent_"):
            inferred_pid = self._pid_from_agent_id(comm)
            if inferred_pid and pid == 0:
                pid = inferred_pid
                if main_pid == 0:
                    main_pid = inferred_pid

        event_data = {
            "type": event_type,
            "pid": pid,
            "ppid": main_pid,
            "timestamp": self._coerce_int(self._field_lookup(fields, "timestamp_ns"), time.time_ns()),
            "comm": comm,
            "data_len": self._coerce_int(self._field_lookup(fields, "bytes"), len(data)),
            "data": data.replace("\\n", "\n").replace("\\r", "\r"),
            "agent_id": agent_id or self._agent_id_for_pid(pid or 0),
            "main_pid": main_pid,
            "_stream": MESSAGE_STREAM,
            "_stream_id": self._safe_decode(stream_id),
        }
        return event_data

    def _normalize_stream_raw_event(self, stream_id, fields):
        if not fields:
            return None

        protocol = self._safe_decode(self._field_lookup(fields, "protocol", ""))
        msg_type = self._safe_decode(self._field_lookup(fields, "type", ""))

        data = self._safe_decode(self._field_lookup(fields, "data", ""))
        agent_id = self._safe_decode(
            self._field_lookup(fields, "agent_id", self._field_lookup(fields, "src", ""))
        )
        pid = self._coerce_int(self._field_lookup(fields, "pid"), 0)
        if pid == 0:
            pid = self._coerce_int(self._field_lookup(fields, "src_pid"), 0)
        if pid == 0:
            pid = self._pid_from_agent_id(agent_id)

        main_pid = self._coerce_int(self._field_lookup(fields, "main_pid"), 0)
        if main_pid == 0:
            main_pid = pid

        if protocol == "stdio":
            event_type = EVENT_STDIO_WRITE if msg_type == "send" else EVENT_STDIO_READ
            source = 1
        elif protocol == "tcp":
            event_type = EVENT_TCP_SEND if msg_type == "send" else EVENT_TCP_RECV
            source = 2
        else:
            event_type = EVENT_TCP_SEND if msg_type == "send" else EVENT_TCP_RECV
            source = 2
            print(f"[ANALYZER] Unrecognized stream protocol '{protocol}', defaulting to TCP")

        comm = self._safe_decode(
            self._field_lookup(fields, "comm", self._field_lookup(fields, "src", protocol))
        )
        if comm.startswith("agent_"):
            inferred_pid = self._pid_from_agent_id(comm)
            if inferred_pid and pid == 0:
                pid = inferred_pid
                if main_pid == 0:
                    main_pid = inferred_pid

        event_data = {
            "type": event_type,
            "pid": pid,
            "ppid": main_pid,
            "timestamp": self._coerce_int(self._field_lookup(fields, "timestamp_ns"), time.time_ns()),
            "comm": comm,
            "data_len": self._coerce_int(self._field_lookup(fields, "bytes"), len(data)),
            "data": data.replace("\\n", "\n").replace("\\r", "\r"),
            "source": source,
            "direction": 0 if msg_type == "recv" else 1,
            "fd": self._coerce_int(self._field_lookup(fields, "fd"), 0),
            "agent_id": agent_id or self._agent_id_for_pid(pid or 0),
            "main_pid": main_pid,
            "_stream": MESSAGE_STREAM,
            "_stream_id": self._safe_decode(stream_id),
        }
        return event_data

    def _poll_message_stream(self):
        if not self.redis_stream_client:
            return []

        try:
            response = self.redis_stream_client.xread(
                {MESSAGE_STREAM: self.message_stream_last_id},
                count=32,
                block=100,
            )
        except Exception as e:
            print(f"[ANALYZER] Failed to read {MESSAGE_STREAM}: {e}")
            return []

        events = []
        for _stream_name, entries in response or []:
            for stream_id, fields in entries:
                self.message_stream_last_id = self._safe_decode(stream_id)
                event_data = self._normalize_stream_event(stream_id, fields)
                if event_data:
                    events.append(event_data)
        return events

    def process_sys_event(self, event_data):
        event_type = event_data.get('type', 'unknown')
        pid = event_data.get('pid', 0)
        uid = event_data.get('uid', 0)
        comm = event_data.get('comm', 'unknown')
        timestamp = event_data.get('timestamp', 0)

        print(f"[ANALYZER] Processing SYS_EVENT | Type: {event_type} | PID: {pid} | UID: {uid} | Comm: {comm}")
        print(f"[ANALYZER]   -> Timestamp: {timestamp} ns")

        if 'filename' in event_data and event_data['filename']:
            print(f"[ANALYZER]   -> Target File: {event_data['filename']}")

        if 'dip' in event_data and 'dport' in event_data:
            print(f"[ANALYZER]   -> Network Target: {event_data['dip']}:{event_data['dport']}")

        inter_alerts = self.inter_analyzer.run_analysis(event_data)
        if inter_alerts:
            print(f"[ANALYZER-INTER] 发现跨进程/关联异常: {inter_alerts}")
            self._push_inter_alerts(inter_alerts, event_data)

        intra_reqs = self.intra_analyzer.analyze_event(event_data)
        if not intra_reqs:
            return []

        results = []
        for req in intra_reqs:
            self._push_intra_request(req)
            result = self.audit_engine.audit_intra_request(req)
            self.sqlite_store.persist_audit_result(req, result)
            print(f"[ANALYZER-AUDIT] 单体审计结果: {result}")
            results.append(result)
        return results

    def process_ssl_event(self, event_data):
        data_val = event_data.get('data', '')
        if data_val and isinstance(data_val, str):
            try:
                decoded = base64.b64decode(data_val).decode('utf-8', errors='replace')
                event_data['data'] = decoded
                if not event_data.get('data_len'):
                    event_data['data_len'] = len(decoded.encode('utf-8', errors='replace'))
            except Exception:
                pass

        event_type = event_data.get('type', 'unknown')
        pid = event_data.get('pid', 0)
        comm = event_data.get('comm', 'unknown')
        data_len = event_data.get('data_len', 0)

        if self.verbose_events:
            print(f"[ANALYZER] Processing SSL event: {event_data}")
            print(f"[ANALYZER]   Event type: {event_type}, PID: {pid}, Comm: {comm}, Data length: {data_len}")

        inter_alerts = self.inter_analyzer.run_analysis(event_data)
        if inter_alerts:
            print(f"[ANALYZER-INTER] 发现跨进程/关联异常: {inter_alerts}")
            self._push_inter_alerts(inter_alerts, event_data)

        intra_reqs = self.intra_analyzer.analyze_event(event_data)
        if not intra_reqs:
            if self.verbose_events:
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

    def process_raw_proto_event(self, event_data):
        """处理纯文本协议事件 (MCP stdio / A2A / ACP / ANP TCP)，含帧解析与字段提取"""
        event_type = event_data.get('type', 0)
        pid = event_data.get('pid', 0)
        fd = event_data.get('fd', 0)
        source = event_data.get('source', 0)
        direction = event_data.get('direction', 0)

        proto_names = {10: "STDIO_READ", 11: "STDIO_WRITE", 12: "TCP_SEND", 13: "TCP_RECV"}
        proto_name = proto_names.get(event_type, "UNKNOWN")
        print(f"[ANALYZER] Processing RAW_PROTO [{proto_name}] pid={pid} fd={fd} src={source} dir={direction}")

        data_b64 = event_data.get('data', '')
        if data_b64:
            try:
                import base64
                decoded = base64.b64decode(data_b64).decode('utf-8', errors='replace')
            except Exception:
                decoded = str(data_b64)
            event_data['data'] = decoded
            if not event_data.get('data_len'):
                event_data['data_len'] = len(decoded.encode('utf-8', errors='replace'))
        else:
            event_data['data'] = ''
            if not event_data.get('data_len'):
                event_data['data_len'] = 0

        if not event_data.get('agent_name'):
            event_data['agent_name'] = self._safe_decode(event_data.get('agent_id', '')) or self._agent_id_for_pid(pid)
        raw_aid = event_data.get('agent_id', '')
        if isinstance(raw_aid, int) and raw_aid > 0:
            event_data['agent_id'] = f"agent_{raw_aid}"
        elif not raw_aid:
            event_data['agent_id'] = event_data.get('agent_name', '') or self._agent_id_for_pid(pid)
        if not event_data.get('ppid'):
            event_data['ppid'] = pid

        # ── 协议指纹 ──
        protocol = fingerprint_protocol(event_data['data'],
                                        source=source, event_type=event_type)
        if protocol:
            event_data['_protocol'] = protocol
            print(f"[ANALYZER] Protocol fingerprint: {protocol}")

        # ── 协议特定帧解析 ──
        data = event_data['data']
        if protocol == "MCP":
            frames = parse_mcp_frames(data)
            event_data['_frames'] = frames
            for frame_str, consumed in frames:
                fields = extract_mcp_fields(frame_str)
                if fields:
                    method = fields.get("method", "")
                    msg_id = fields.get("msg_id")
                    print(f"[ANALYZER]   MCP frame: method={method} id={msg_id} "
                          f"result={fields.get('has_result')} error={fields.get('has_error')}")
                    if not event_data.get('filename'):
                        event_data['filename'] = method

        elif protocol == "A2A":
            sse_events = parse_sse_events(data)
            event_data['_sse_events'] = sse_events
            for evt in sse_events:
                task_id = extract_a2a_task_id(evt)
                evt_type = evt.get("event", "")
                if task_id:
                    print(f"[ANALYZER]   A2A event: type={evt_type} taskId={task_id}")
            card = extract_a2a_agent_card(data)
            if card:
                capabilities = card.get("capabilities", {})
                skills = capabilities.get("skills", []) if isinstance(capabilities, dict) else []
                print(f"[ANALYZER]   A2A agent-card: skills={len(skills)} "
                      f"modes={capabilities.get('defaultInputModes', []) if isinstance(capabilities, dict) else '?'}")

        elif protocol == "ACP":
            http_info = split_http_message(data)
            ct = http_info.get("content_type", "")
            if ct and "boundary" in ct:
                parts = parse_acp_multipart(data, ct)
                event_data['_acp_parts'] = parts
                print(f"[ANALYZER]   ACP multipart: {len(parts)} parts")
            acp_headers = extract_acp_headers(http_info.get("headers", data))
            if acp_headers:
                event_data['_acp_headers'] = acp_headers
                print(f"[ANALYZER]   ACP headers: {list(acp_headers.keys())}")

        elif protocol == "ANP":
            graph = extract_anp_graph(data)
            if graph:
                event_data['_anp_graph'] = graph
                print(f"[ANALYZER]   ANP graph: {len(graph)} nodes")
            dids = extract_anp_dids(data)
            if dids:
                event_data['_dids'] = dids
                print(f"[ANALYZER]   ANP DIDs: {dids[:5]}")

        inter_alerts = self.inter_analyzer.run_analysis(event_data)
        if inter_alerts:
            print(f"[ANALYZER-INTER] 发现跨进程/关联异常: {inter_alerts}")
            self._push_inter_alerts(inter_alerts, event_data)

        intra_reqs = self.intra_analyzer.analyze_event(event_data)
        if not intra_reqs:
            return []

        results = []
        for req in intra_reqs:
            self._push_intra_request(req)
            result = self.audit_engine.audit_intra_request(req)
            self.sqlite_store.persist_audit_result(req, result)
            print(f"[ANALYZER-AUDIT] 协议审计结果: {result}")
            results.append(result)
        return results

    @staticmethod
    def _fingerprint_protocol(event_data):
        """统一协议指纹 (委托给 protocol_fingerprint 模块)"""
        data = event_data.get('data', '') or ''
        source = event_data.get('source', 0)
        event_type = event_data.get('type', 0)
        return fingerprint_protocol(data, source=source, event_type=event_type)

    def run(self):
        print("[ANALYZER] Starting Main Analyzer...")
        print("[ANALYZER] Waiting for events from Redis channel...")

        if not self.connect_redis():
            print("[ANALYZER] Cannot proceed without Redis connection")
            return

        print("[ANALYZER] Listening for events on channel:", REDIS_CHANNEL)
        print("[ANALYZER] Following stream:", MESSAGE_STREAM)

        try:
            while True:
                message = self.pubsub.get_message(timeout=1.0)
                if message and self._safe_decode(message.get('type')) == 'message':
                    raw_data = self._safe_decode(message.get('data'))
                    try:
                        event_data = json.loads(raw_data)
                    except json.JSONDecodeError as e:
                        print(f"[ANALYZER] Skip malformed pubsub event: {e}")
                        continue
                    self.sqlite_store.persist_event(event_data)

                    event_type = event_data.get('type', 0)
                    if event_type in (EVENT_EXECVE, EVENT_FORK, EVENT_OPEN, EVENT_UNLINK, EVENT_CONNECT, EVENT_CHMOD, EVENT_AGENT_COMM):
                        print(f"[ANALYZER] Received event: {event_data}")
                        self.process_sys_event(event_data)
                    elif event_type in (EVENT_SSL_READ, EVENT_SSL_WRITE):
                        if self.process_ssl_pubsub:
                            self._log_event_summary("event", event_data)
                            self.process_ssl_event(event_data)
                        elif self.verbose_events:
                            print("[ANALYZER] Skip SSL pubsub event; using inter:messages stream")
                    elif event_type in (EVENT_STDIO_READ, EVENT_STDIO_WRITE, EVENT_TCP_SEND, EVENT_TCP_RECV):
                        self._log_event_summary("raw_proto", event_data)
                        self.process_raw_proto_event(event_data)
                    else:
                        print(f"[ANALYZER] Unknown event type: {event_type}")

                for event_data in self._poll_message_stream():
                    self.sqlite_store.persist_event(event_data)
                    event_type = event_data.get('type', 0)
                    if event_type in (EVENT_SSL_READ, EVENT_SSL_WRITE):
                        if self.log_ssl_events:
                            self._log_event_summary("stream event", event_data)
                        if not self._should_process_ssl_event(event_data):
                            continue
                        self.process_ssl_event(event_data)
                    elif event_type in (EVENT_STDIO_READ, EVENT_STDIO_WRITE, EVENT_TCP_SEND, EVENT_TCP_RECV):
                        if self.log_ssl_events:
                            self._log_event_summary("stream raw_proto", event_data)
                        self.process_raw_proto_event(event_data)

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
            if self.redis_stream_client:
                self.redis_stream_client.close()
            self.sqlite_store.close()
            print("[ANALYZER] Main Analyzer shutdown complete")


if __name__ == "__main__":
    print("=" * 60)
    print("[ANALYZER] eBPF Multi-Agent Monitor - Main Analyzer")
    print("=" * 60)

    analyzer = MainAnalyzer()
    analyzer.run()
