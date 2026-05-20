#!/usr/bin/env bash
set -euo pipefail

prompt="${1:-}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
secret_file="${script_dir}/deepseek.env"

# 优先加载本地私有配置
if [[ -f "$secret_file" ]]; then
  # shellcheck disable=SC1090
  source "$secret_file"
fi

DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}"
DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-chat}"
DEEPSEEK_BASE_URL="${DEEPSEEK_BASE_URL:-https://api.deepseek.com}"

if [[ -z "$DEEPSEEK_API_KEY" ]]; then
  echo "UNSURE"
  exit 0
fi

if [[ -z "$prompt" ]]; then
  echo "UNSURE"
  exit 0
fi

json_escape() {
  printf '%s' "$1" \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
    | sed ':a;N;$!ba;s/\n/\\n/g'
}

esc_prompt="$(json_escape "$prompt")"

body=$(cat <<JSON
{
  "model": "${DEEPSEEK_MODEL}",
  "temperature": 0,
  "max_tokens": 4,
  "messages": [
    {
      "role": "system",
      "content": "You are a strict host-security reviewer. Return exactly one token: CONFIRM, SUPPRESS, or UNSURE. Prefer CONFIRM for high-risk operations (shell exec, sensitive file access, out-of-workspace destructive ops)."
    },
    {
      "role": "user",
      "content": "${esc_prompt}"
    }
  ]
}
JSON
)

resp="$(curl -sS --max-time 15 \
  -H "Authorization: Bearer ${DEEPSEEK_API_KEY}" \
  -H "Content-Type: application/json" \
  -X POST "${DEEPSEEK_BASE_URL}/chat/completions" \
  -d "$body" 2>/dev/null || true)"

if [[ -z "$resp" ]]; then
  echo "UNSURE"
  exit 0
fi

extract_content() {
  local r="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.choices[0].message.content // empty' <<<"$r" 2>/dev/null || true
    return
  fi
  # fallback: best-effort parse when jq is unavailable
  echo "$r" | sed -n 's/.*"content":"\([^"]*\)".*/\1/p' | head -n 1
}

content="$(extract_content "$resp")"
upper="$(echo "$content" | tr '[:lower:]' '[:upper:]')"

if [[ "$upper" == *"SUPPRESS"* ]]; then
  echo "SUPPRESS"
elif [[ "$upper" == *"CONFIRM"* ]]; then
  echo "CONFIRM"
elif [[ "$upper" == *"UNSURE"* ]]; then
  echo "UNSURE"
else
  echo "UNSURE"
fi
