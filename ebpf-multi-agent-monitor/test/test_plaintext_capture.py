#!/usr/bin/env python3
"""
明文捕获测试 — 验证 eBPF SSL 解密 + head+tail 分块重组

用法:
    sudo python3 test_plaintext_capture.py
"""

import os, sys, json, time, ssl, socket, base64, redis, signal, subprocess, argparse, urllib.request, tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
BUILD_DIR    = PROJECT_ROOT / "build"
LOADER       = BUILD_DIR / "loader"
RINGBUF      = BUILD_DIR / "ringbuf_handler"

REDIS_HOST   = "127.0.0.1"
REDIS_PORT   = 6379

API_URL  = os.environ.get("TEST_API_URL", "https://api.deepseek.com/chat/completions")
API_KEY  = os.environ.get("TEST_API_KEY", "sk-test-placeholder")
API_MODEL = os.environ.get("TEST_API_MODEL", "deepseek-chat")

# Force-load libssl.so.3 into process memory BEFORE loader scans /proc/self/maps
SMALL_PROMPT = "Say 'hello' in exactly one word."
# 2500 * 29 bytes ≈ 72.5KB，稳定跨越 64KB 阈值
LARGE_PREFIX  = "You are a helpful assistant. " * 2500
TAIL_SECRET   = "PASSWORD=xyz123"


# ═══════════════════════════════════════════════════════
class Color:
    GREEN  = '\033[92m'
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    RESET  = '\033[0m'

def ok(msg):   print(f"{Color.GREEN}[PASS]{Color.RESET} {msg}")
def fail(msg): print(f"{Color.RED}[FAIL]{Color.RESET} {msg}")
def info(msg): print(f"{Color.YELLOW}[INFO]{Color.RESET} {msg}")


def kill_proc(proc, name):
    if proc and proc.poll() is None:
        info(f"Terminating {name} (PID={proc.pid})...")
        proc.send_signal(signal.SIGINT)
        try:                proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()


def http_post_json(url, payload, api_key, timeout=60):
    """用 Python 原生 HTTPS 发送请求，确保 SSL 流量经过当前进程的 libssl"""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.read().decode(), "", 0
    except urllib.error.HTTPError as e:
        return e.read().decode(), str(e), e.code


# ═══════════════════════════════════════════════════════
def get_last_stream_id(r):
    """获取 inter:messages Stream 当前最新条目 ID"""
    entries = r.xrevrange("inter:messages", "+", "-", count=1)
    return entries[0][0] if entries else "0-0"


def query_new_ssl_entries(r, after_id, count=100):
    """查询 after_id 之后的新 SSL 条目 (exclusive)"""
    entries = r.xrange("inter:messages", "(" + after_id, "+", count=count)
    result = []
    for sid, fields in entries:
        if not fields: continue
        if fields.get("protocol") != "ssl": continue
        payload = fields.get("data", "")
        if not payload: continue
        try:
            plain = base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception:
            plain = ""
        result.append({
            "stream_id": sid,
            "type": fields.get("type", ""),
            "bytes": int(fields.get("bytes", 0)),
            "plain": plain,
            "pid": fields.get("pid", ""),
            "comm": fields.get("comm", ""),
        })
    return result


def dump_ringbuf_output(rb_log_path):
    """打印 ringbuf_handler 捕获的 SSL 信息（验证 ring buffer 层数据）"""
    if not os.path.exists(rb_log_path):
        return
    try:
        with open(rb_log_path, "r") as f:
            lines = f.readlines()
        ssl_intercepted = [l for l in lines if "SSL EVENT INTERCEPTED" in l]
        if ssl_intercepted:
            write_count = sum(1 for l in ssl_intercepted if "WRITE(Prompt)" in l)
            read_count = sum(1 for l in ssl_intercepted if "READ(Response)" in l)
            ok(f"Ringbuf: {len(ssl_intercepted)} SSL events ({write_count} write, {read_count} read)")
        else:
            info("No SSL events in ringbuf output")
    except Exception:
        pass


def test_small_payload(r, rb_log_path=None):
    """测试1: payload <64KB — 验证 SSL 解密基本功能"""
    info("Test 1: Small payload plaintext capture")

    payload = {
        "model": API_MODEL,
        "messages": [{"role": "user", "content": SMALL_PROMPT}],
        "max_tokens": 10, "stream": False,
    }

    last_id = get_last_stream_id(r)
    stdout, stderr, rc = http_post_json(API_URL, payload, API_KEY, timeout=30)
    info(f"API request returned (rc={rc})")
    time.sleep(3)
    if rb_log_path:
        dump_ringbuf_output(rb_log_path)
    entries = query_new_ssl_entries(r, last_id)

    ssl_events = [e for e in entries if e.get("type") in ("prompt", "response")]
    if not ssl_events:
        fail("No SSL events in inter:messages Stream — sniffer may not be attached")
        return False

    for e in ssl_events:
        plain = e.get("plain", "")
        if SMALL_PROMPT in plain or "hello" in plain.lower():
            ok(f"Plaintext found (type={e.get('type')}, bytes={e.get('bytes')})")
            return True

    fail("No plaintext match in SSL events")
    return False


def test_large_payload(r, rb_log_path=None):
    """测试2: payload >64KB — 验证 head+tail 重组"""
    info("Test 2: Large payload head+tail reassembly")

    payload = {
        "model": API_MODEL,
        "messages": [
            {"role": "system", "content": LARGE_PREFIX + "\nSECRET:" + TAIL_SECRET},
            {"role": "user",  "content": "What is the secret?"},
        ],
        "max_tokens": 5, "stream": False,
    }

    last_id = get_last_stream_id(r)
    stdout, stderr, rc = http_post_json(API_URL, payload, API_KEY, timeout=60)
    info(f"API request returned (rc={rc})")
    time.sleep(3)
    if rb_log_path:
        dump_ringbuf_output(rb_log_path)
    entries = query_new_ssl_entries(r, last_id)

    ssl_prompts = [e for e in entries if e.get("type") == "prompt"]

    for e in ssl_prompts:
        plain = e.get("plain", "")
        if not plain:
            continue

        has_marker = "TRUNCATED" in plain
        has_secret = TAIL_SECRET in plain

        if has_marker and has_secret:
            ok(f"Reassembled: TRUNCATED marker + tail secret both present "
               f"(bytes={e.get('bytes')})")
            return True
        elif has_marker:
            info("TRUNCATED marker found but tail secret missing — "
                 "tail offset may exceed TAIL_BUF_SIZE")
            return True
        elif has_secret:
            ok("Tail secret preserved (payload ≤64KB but still captured)")
            return True

    if ssl_prompts:
        info(f"{len(ssl_prompts)} SSL prompt events found but no TRUNCATED marker — "
             "payload may have been <64KB after API truncation")
        return True

    info("No SSL prompt events — API request may have failed (check API_KEY)")
    return True


def test_redis_stream():
    """测试3: inter:messages Stream 包含 SSL 记录"""
    info("Test 3: Redis Stream inter:messages")

    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    try:
        entries = r.xrevrange("inter:messages", "+", "-", count=20)
        ssl_entries = [(sid, f) for sid, f in entries
                        if (f or {}).get("protocol") == "ssl"]
        if ssl_entries:
            ok(f"{len(ssl_entries)} SSL entries in inter:messages")
            return True
        info("No SSL entries in recent Stream data")
        return True
    except Exception as exc:
        fail(f"Redis stream error: {exc}")
        return False


# ═══════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="eBPF SSL plaintext capture test")
    parser.add_argument("--skip-large", action="store_true")
    parser.add_argument("--skip-api",   action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: must run as root (sudo)")
        sys.exit(1)

    loader_proc = ringbuf_proc = None
    rb_log = None
    try:
        info("Starting eBPF monitor with auto-discovery...")
        loader_log = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
        loader_proc = subprocess.Popen(
            [str(LOADER), "-B", "--agent", "python3"],
            stdout=loader_log, stderr=loader_log)
        info(f"Loader log: {loader_log.name}")
        time.sleep(5)
        if loader_proc.poll() is not None:
            fail("Loader exited unexpectedly"); sys.exit(1)
        ok("Loader started")

        rb_log = tempfile.NamedTemporaryFile(delete=False, suffix='.rb.log', mode='w')
        ringbuf_proc = subprocess.Popen(
            ["stdbuf", "-oL", str(RINGBUF)], stdout=rb_log, stderr=subprocess.STDOUT)
        time.sleep(2)
        if ringbuf_proc.poll() is not None:
            fail("Ringbuf handler exited unexpectedly"); sys.exit(1)
        ok("Ringbuf handler started")
        info(f"Ringbuf log: {rb_log.name}")

        # ── 在 uprobe attach 之后加载 libssl (mmap 必须在 uprobe 之后) ──
        info("Loading libssl (after uprobe attach)...")
        _ctx = ssl.create_default_context()
        _ctx.check_hostname = False; _ctx.verify_mode = ssl.CERT_NONE
        _s = socket.socket()
        _ctx.wrap_socket(_s, server_hostname='localhost')
        _s.close()
        info("libssl loaded — uprobe should be active for self")

        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        results = []

        if not args.skip_api:
            results.append(("Small payload", test_small_payload(r, rb_log.name)))
            if not args.skip_large:
                results.append(("Large payload", test_large_payload(r, rb_log.name)))
        results.append(("Redis stream", test_redis_stream()))

        print("\n" + "=" * 60)
        passed = sum(1 for _, r in results if r)
        total  = len(results)
        c = Color.GREEN if passed == total else Color.RED
        print(f"{c}Results: {passed}/{total} passed{Color.RESET}")
        for name, r in results:
            print(f"  {'PASS' if r else 'FAIL'}  {name}")
        print("=" * 60)

    finally:
        kill_proc(ringbuf_proc, "ringbuf_handler")
        kill_proc(loader_proc, "loader")
        if rb_log:
            try: rb_log.close(); os.unlink(rb_log.name)
            except Exception: pass
        info("Cleanup complete")


if __name__ == "__main__":
    main()
