#!/bin/bash
set -e

API_TOKEN=${API_TOKEN:-$(python3 -c "import secrets; print(secrets.token_hex(16))")}
MAX_CONCURRENT=${MAX_CONCURRENT:-10}
SQLMAPAPI_PORT=${SQLMAPAPI_PORT:-8775}
SQLMAP_DNS_PORT=${SQLMAP_DNS_PORT:-}
SQLMAP_DNS_PORT_RANGE_START=${SQLMAP_DNS_PORT_RANGE_START:-30000}
SQLMAP_DNS_PORT_RANGE_END=${SQLMAP_DNS_PORT_RANGE_END:-40000}
SQLMAPSH_AGENT_BIN=${SQLMAPSH_AGENT_BIN:-/usr/local/bin/sqlmapsh-agent}
PUBLIC_HOST=${PUBLIC_HOST:-}
HOST_PORT=${HOST_PORT:-5000}

export PYTHONPATH="/opt/sqlmap-hooks${PYTHONPATH:+:${PYTHONPATH}}"
export SQLMAP_DNS_PORT
export SQLMAP_DNS_PORT_RANGE_START
export SQLMAP_DNS_PORT_RANGE_END
export SQLMAP_REAL_PATH="/opt/sqlmap-source/sqlmap.py"
export SQLMAP_REAL_PYTHON="python3"
export SQLMAP_API_WRAPPER="/usr/local/bin/sqlmapsh-agent"

mkdir -p /app/output
SQLMAPAPI_LOG=/app/output/sqlmapapi.log
touch "$SQLMAPAPI_LOG"

if [ ! -f /opt/sqlmap-source/sqlmapapi.py ]; then
  mkdir -p /opt/sqlmap-source
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap-source >/dev/null 2>&1 || true
fi

SQLMAPAPI_BIN=/opt/sqlmap-source/sqlmapapi.py
if [ ! -f "$SQLMAPAPI_BIN" ]; then
  mkdir -p /opt/sqlmap-source
  curl -fsSL https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.tar.gz | tar xz -C /opt/sqlmap-source --strip-components=1
fi

if [ ! -x "$SQLMAPSH_AGENT_BIN" ]; then
  echo "sqlmapsh agent binary not found: $SQLMAPSH_AGENT_BIN"
  exit 1
fi

cat > /usr/local/bin/sqlmap <<'EOF'
#!/bin/sh
exec /usr/local/bin/sqlmapsh-agent "$@"
EOF
chmod +x /usr/local/bin/sqlmap

echo "sqlmapapi log: $SQLMAPAPI_LOG"
python3 "$SQLMAPAPI_BIN" -s -H 127.0.0.1 -p "$SQLMAPAPI_PORT" >>"$SQLMAPAPI_LOG" 2>&1 &
sleep 2

if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST=$(curl -fsSL https://api.ipify.org 2>/dev/null || true)
fi
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST=$(hostname -I | awk '{print $1}')
fi

ENCODED=$(python3 -c "import base64,json; d={'name':'${AGENT_NAME:-agent}','url':'http://${PUBLIC_HOST}:${HOST_PORT}','api_key':'${API_TOKEN}','max_concurrency':int('${MAX_CONCURRENT}')}; print('sqlmapagent://' + base64.b64encode(json.dumps(d).encode()).decode())")

echo "Agent URL: http://${PUBLIC_HOST}:${HOST_PORT}"
echo "API Token: ${API_TOKEN}"
echo "${ENCODED}"

exec python3 /app/sqlmap_agent.py --sqlmapapi-port "$SQLMAPAPI_PORT" --flask-port 5000 --api-token "$API_TOKEN" --max-concurrent "$MAX_CONCURRENT"
