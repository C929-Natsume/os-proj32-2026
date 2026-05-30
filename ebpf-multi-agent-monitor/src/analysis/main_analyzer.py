#!/usr/bin/env python3
import sys
import time
import redis
import json
from audit_engine import AuditEngine
from intra_agent.main import IntraAgentAnalyzer
# 1. 新增：导入多智能体协同分析模块
from inter_agent.main import InterAgentAnalyzer

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_CHANNEL = "ebpf_events"

class MainAnalyzer:
    def __init__(self):
        print("[ANALYZER] Initializing Main Analyzer...")
        self.redis_client = None
        self.pubsub = None
        self.audit_engine = AuditEngine()
        
        # 初始化单体分析器
        self.intra_analyzer = IntraAgentAnalyzer()
        # 2. 新增：初始化多体协同分析器
        self.inter_analyzer = InterAgentAnalyzer() 
        
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
            print(f"[ANALYZER-INTER] 发现多体协同异常: {inter_alerts}")

        # 路由 2: 交给 Intra-Agent
        intra_reqs = self.intra_analyzer.analyze_event(event_data)
        if not intra_reqs:
            return []

        # 路由 3: 送入审计引擎
        results = []
        for req in intra_reqs:
            result = self.audit_engine.audit_intra_request(req)
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

        # SSL 流量目前主要属于单体行为分析的范畴
        intra_reqs = self.intra_analyzer.analyze_event(event_data)
        if not intra_reqs:
            print("[ANALYZER]   无单体审计请求")
            return []

        results = []
        for req in intra_reqs:
            result = self.audit_engine.audit_intra_request(req)
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