#!/usr/bin/env python
"""Check VM environment for AutoGen + Ollama."""
import autogen
print('pyautogen:', autogen.__version__)

import json, urllib.request
req = urllib.request.Request('http://localhost:11434/api/tags')
try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        d = json.loads(resp.read().decode())
        print('Ollama models:', [m['name'] for m in d.get('models', [])])
except Exception as e:
    print('Ollama check failed:', e)
