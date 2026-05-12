#!/bin/bash
set -euo pipefail

PYTHON_BIN="${PATH_AGENT_PYTHON:-/opt/path-agent-venv/bin/python}"
API_TOKEN="${API_TOKEN:-$("$PYTHON_BIN" -c "import secrets; print(secrets.token_hex(16))")}"
MAX_CONCURRENT="${MAX_CONCURRENT:-5}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
HOST_PORT="${HOST_PORT:-5000}"

mkdir -p /app/output

if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
fi
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(hostname -I | awk '{print $1}')"
fi

exec "$PYTHON_BIN" /app/path_agent.py --flask-port 5000 --api-token "$API_TOKEN" --max-concurrent "$MAX_CONCURRENT"
