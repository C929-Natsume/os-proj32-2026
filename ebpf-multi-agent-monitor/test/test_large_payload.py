#!/usr/bin/env python3
"""
超长文本 N-Chunk 验证测试（修复版）

验证: >64KB 的 SSL_write 被分为 N 块，用户态完整拼接重组。

用法:
    sudo TEST_API_KEY="sk-xxx" python3 test_large_payload.py
"""

import os, sys, time, json, base64, uuid, signal, subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
BUILD_DIR    = PROJECT_ROOT / "build"
LOADER       = BUILD_DIR / "loader"
RINGBUF      = BUILD_DIR / "ringbuf_handler"
REDIS_HOST   = "127.0.0.1"
REDIS_PORT   = 6379

API_URL      = "https://api.deepseek.com/chat/completions"
API_KEY      = os.environ.get("TEST_API_KEY", "sk-test")
API_MODEL    = "deepseek-chat"

TAIL_MARKER  = str(uuid.uuid4())
LARGE_PROMPT = ("The quick brown fox jumps over the lazy dog. " * 1500) \
             + "\nTAIL_MARKER: " + TAIL_MARKER

print(f"[TEST] Prompt: {len(LARGE_PROMPT)} bytes, "
      f"chunks: {(len(LARGE_PROMPT) + 65535) // 65536}")


def kill_proc(proc, name):
    if proc and proc.poll() is None:
        print(f"[TEST] Terminating {name}...")
        proc.send_signal(signal.SIGINT)
        try: proc.wait(timeout=5)
        except: proc.kill()


loader = ringbuf = None
try:
    # ── 1. Start loader ──
    print("[TEST] Starting loader...")
    loader = subprocess.Popen(
        [str(LOADER), "--agent", "python3"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    assert loader.poll() is None, "Loader failed"
    print("[TEST] Loader started")

    # ── 2. Start ringbuf ──
    print("[TEST] Starting ringbuf handler...")
    ringbuf = subprocess.Popen(
        [str(RINGBUF)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    assert ringbuf.poll() is None, "Ringbuf handler failed"
    print("[TEST] Ringbuf handler started")

    # ── 3. Wait for auto-discovery + Force-load libssl AFTER uprobe ──
    print("[TEST] Waiting for auto-discovery to register python3 PIDs...")
    time.sleep(12)  # 6 scan cycles × 2 seconds each

    # ── 4. Force-load libssl now (mmap AFTER uprobe) ──
    import ssl, socket
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE
    _s = socket.socket()
    _ctx.wrap_socket(_s, server_hostname='localhost')
    _s.close()
    print("[TEST] libssl loaded (after uprobe)")

    # Auto-discovery needs to re-scan to register self PID with libssl
    time.sleep(4)

    # ── 5. Send HTTPS request ──
    import urllib.request

    data = json.dumps({
        "model": API_MODEL,
        "messages": [
            {"role": "system", "content": LARGE_PROMPT},
            {"role": "user", "content": "Reply with the tail marker."}
        ],
        "max_tokens": 5
    }).encode()

    req = urllib.request.Request(API_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {API_KEY}")

    ctx2 = ssl.create_default_context()
    print("[TEST] Sending >64KB HTTPS request...")
    try:
        resp = urllib.request.urlopen(req, timeout=60, context=ctx2)
        print(f"[TEST] API response: {resp.read().decode()[:200]}")
    except Exception as e:
        print(f"[TEST] API error: {e}")

    # ── 6. Verify Redis ──
    time.sleep(3)
    import redis
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe("ebpf_events")
    events = []
    deadline = time.time() + 5
    while time.time() < deadline:
        msg = pubsub.get_message(timeout=0.5)
        if msg and msg.get("type") == "message":
            try: events.append(json.loads(msg["data"]))
            except: pass
    pubsub.close()

    ssl_writes = [e for e in events if e.get("type") == 7]
    print(f"\n[TEST] SSL_WRITE events in Redis: {len(ssl_writes)}")

    found = False
    for e in ssl_writes:
        try:
            plain = base64.b64decode(e["data"]).decode("utf-8", errors="replace")
        except:
            continue
        if TAIL_MARKER in plain:
            data_len = e.get("data_len", 0)
            print(f"\n✅ N-CHUNK REASSEMBLY SUCCESS!")
            print(f"   Original total: {data_len:,} bytes")
            print(f"   Decoded plain:  {len(plain):,} bytes (expected ~{data_len})")
            print(f"   Tail marker:    {TAIL_MARKER}")
            if len(plain) > 65540:
                print(f"   Chunk seam at 65536: {repr(plain[65536:65550])}")
            found = True
            break

    if not found:
        print(f"\n❌ N-CHUNK REASSEMBLY FAILED")
        print(f"   Tail marker: {TAIL_MARKER}")
        for e in ssl_writes[:3]:
            try:
                p = base64.b64decode(e.get("data", "")).decode("utf-8", errors="replace")[:80]
                print(f"   data_len={e.get('data_len')} preview={p}...")
            except: pass
        sys.exit(1)

finally:
    kill_proc(ringbuf, "ringbuf_handler")
    kill_proc(loader, "loader")
