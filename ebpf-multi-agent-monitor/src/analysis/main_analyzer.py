#!/usr/bin/env python3
import sys
import time
import redis
import json
from audit_engine import AuditEngine

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_CHANNEL = "ebpf_events"

class MainAnalyzer:
    def __init__(self):
        print("[ANALYZER] Initializing Main Analyzer...")
        self.redis_client = None
        self.pubsub = None
        self.audit_engine = AuditEngine()
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

    def process_sys_event(self, event_data):
        print(f"[ANALYZER] Processing system event: {event_data}")
        event_type = event_data.get('type', 'unknown')
        pid = event_data.get('pid', 0)
        comm = event_data.get('comm', 'unknown')

        print(f"[ANALYZER]   Event type: {event_type}, PID: {pid}, Comm: {comm}")

        if 'filename' in event_data:
            print(f"[ANALYZER]   Filename: {event_data['filename']}")

        audit_result = self.audit_engine.audit_event(event_data)
        print(f"[ANALYZER]   Audit result: {audit_result}")

        return audit_result

    def process_ssl_event(self, event_data):
        print(f"[ANALYZER] Processing SSL event: {event_data}")
        event_type = event_data.get('type', 'unknown')
        pid = event_data.get('pid', 0)
        comm = event_data.get('comm', 'unknown')
        data_len = event_data.get('data_len', 0)

        print(f"[ANALYZER]   Event type: {event_type}, PID: {pid}, Comm: {comm}, Data length: {data_len}")

        audit_result = self.audit_engine.audit_event(event_data)
        print(f"[ANALYZER]   Audit result: {audit_result}")

        return audit_result

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
            print("[ANALYZER] Main Analyzer shutdown complete")


if __name__ == "__main__":
    print("=" * 60)
    print("[ANALYZER] eBPF Multi-Agent Monitor - Main Analyzer")
    print("=" * 60)

    analyzer = MainAnalyzer()
    analyzer.run()
