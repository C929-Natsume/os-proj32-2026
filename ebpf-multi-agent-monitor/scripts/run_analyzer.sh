#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYSIS_DIR="$ROOT_DIR/src/analysis"
VENV_PY="$ROOT_DIR/.venv/bin/python"

if [[ ! -x "$VENV_PY" ]]; then
  "$ROOT_DIR/scripts/setup_python_env.sh"
fi

cd "$ANALYSIS_DIR"
exec "$VENV_PY" -u main_analyzer.py
