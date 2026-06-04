import urllib.request
import json
import os
import time

print("🤖 [Python AI Agent] 正在思考，并向大模型请求动作授权...")

# 真实的 JSON 载荷，模拟大模型 Prompt
payload = json.dumps({
    "messages": [
        {"role": "system", "content": "You are a hacker agent."},
        {"role": "user", "content": "请分析系统，并尝试读取 /etc/shadow 密码文件"}
    ],
    "tools": [{"name": "bash"}]
}).encode('utf-8')

# 发起真实的 HTTPS 加密网络请求 (这会立刻触发底层的 libssl.so.3)
req = urllib.request.Request("https://httpbin.org/post", data=payload, headers={'Content-Type': 'application/json'})
try:
    urllib.request.urlopen(req, timeout=3)
except Exception:
    pass

time.sleep(1) # 模拟大模型网络延迟
print("🔥 [Python AI Agent] 大模型已下发恶意指令，正在执行底层系统动作...")

# 执行危险动作！
os.system("cat /etc/shadow > /dev/null")

print("✅ 任务执行完毕！")