"""Quick Ollama test with tinyllama."""
import urllib.request, json, time, sys

model = sys.argv[1] if len(sys.argv) > 1 else "tinyllama"
t0 = time.time()
req = urllib.request.Request(
    'http://localhost:11434/api/generate',
    json.dumps({"model": model, "prompt": "say hello", "stream": False}).encode(),
    {"Content-Type": "application/json"}
)
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        d = json.loads(resp.read().decode())
        print(f"{model} OK in {time.time()-t0:.1f}s:", d.get("response", "")[:60])
except Exception as e:
    print(f"{model} FAILED after {time.time()-t0:.1f}s:", e)
    sys.exit(1)
