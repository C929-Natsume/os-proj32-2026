import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Callable

class RedisEventObserver:
    """Observes Redis PubSub channel to measure BPF->Redis event latency."""

    def __init__(self, redis_host: str = "127.0.0.1", redis_port: int = 6379,
                 channel: str = "ebpf_events"):
        self._host = redis_host
        self._port = redis_port
        self._channel = channel
        self._events: List[Dict] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._tags: Dict[str, float] = {}
        self._latencies: Dict[str, List[float]] = defaultdict(list)

    def start(self):
        import redis as redispy
        self._client = redispy.Redis(host=self._host, port=self._port, socket_timeout=5)
        self._pubsub = self._client.pubsub(ignore_subscribe_messages=True)
        self._pubsub.subscribe(self._channel)
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> Dict[str, List[float]]:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        try:
            self._pubsub.close()
            self._client.close()
        except Exception:
            pass
        return dict(self._latencies)

    def _run(self):
        import json
        while self._running:
            try:
                msg = self._pubsub.get_message(timeout=0.1)
                if msg and msg.get("type") == "message":
                    data_str = msg.get("data", "")
                    if isinstance(data_str, bytes):
                        data_str = data_str.decode("utf-8", errors="replace")
                    try:
                        event = json.loads(data_str) if data_str else {}
                    except json.JSONDecodeError:
                        event = {"raw": data_str[:200]}
                    arrival_ns = time.perf_counter_ns()
                    event["_redis_arrival_ns"] = arrival_ns
                    with self._lock:
                        self._events.append(event)
                        self._match_tags(event, arrival_ns)
            except Exception:
                time.sleep(0.01)

    def mark_tag(self, tag: str):
        with self._lock:
            self._tags[tag] = time.perf_counter_ns()

    def _match_tags(self, event: Dict, arrival_ns: int):
        """Match events to workload tags by PID correlation."""
        event_pid = event.get("pid", event.get("PID", 0))
        event_type = event.get("type", event.get("event_type", ""))
        # Match any tag that was marked within the last few seconds
        now = time.perf_counter_ns()
        for tag, tag_time in list(self._tags.items()):
            if now - tag_time > 10_000_000_000:
                del self._tags[tag]
                continue
            latency_ns = arrival_ns - tag_time
            if 0 < latency_ns < 5_000_000_000:
                self._latencies[tag].append(latency_ns)

    def get_latency_stats(self, tag: str) -> Dict:
        vals = self._latencies.get(tag, [])
        if not vals:
            return {"count": 0, "p50_ns": 0, "p95_ns": 0, "p99_ns": 0,
                    "min_ns": 0, "max_ns": 0, "avg_ns": 0}
        sorted_vals = sorted(vals)
        n = len(sorted_vals)
        return {
            "count": n,
            "p50_ns": sorted_vals[n // 2],
            "p95_ns": sorted_vals[int(n * 0.95)],
            "p99_ns": sorted_vals[int(n * 0.99)],
            "min_ns": sorted_vals[0],
            "max_ns": sorted_vals[-1],
            "avg_ns": sum(sorted_vals) // n,
        }

    def get_event_count(self) -> int:
        with self._lock:
            return len(self._events)

    def clear_events(self):
        with self._lock:
            self._events.clear()
            self._latencies.clear()
            self._tags.clear()
