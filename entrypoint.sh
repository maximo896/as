#!/bin/bash
set -e

API_TOKEN=${API_TOKEN:-$(python3 -c "import secrets; print(secrets.token_hex(16))")}
MAX_CONCURRENT=${MAX_CONCURRENT:-10}
SQLMAPAPI_PORT=${SQLMAPAPI_PORT:-$(python3 -c "import random; print(random.randint(20000,60000))")}

echo "[*] Sqlmap Agent starting..."
echo "[*] API_TOKEN: $API_TOKEN"
echo "[*] MAX_CONCURRENT: $MAX_CONCURRENT"
echo "[*] SQLMAPAPI_PORT: $SQLMAPAPI_PORT"

mkdir -p /app/output

if ! command -v sqlmapapi.py &>/dev/null; then
    echo "[*] Downloading sqlmap source for sqlmapapi.py..."
    if command -v git &>/dev/null; then
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /tmp/sqlmap-source
    else
        mkdir -p /tmp/sqlmap-source
        curl -sL https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.tar.gz | tar xz -C /tmp/sqlmap-source --strip-components=1
    fi
fi

SQLMAPAPI_BIN="/tmp/sqlmap-source/sqlmapapi.py"

echo "[*] Starting sqlmapapi on port $SQLMAPAPI_PORT..."
python3 "$SQLMAPAPI_BIN" -s -H 127.0.0.1 -p "$SQLMAPAPI_PORT" &
sleep 3

echo "[*] Starting Sqlmap Agent..."

SERVER_IP=${SERVER_IP:-$(hostname -I | awk '{print $1}')}
if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "127.0.0.1" ]; then
    SERVER_IP="YOUR_SERVER_IP"
fi

python3 /app/sqlmap_agent.py \
    --sqlmapapi-port "$SQLMAPAPI_PORT" \
    --api-token "$API_TOKEN" \
    --max-concurrent "$MAX_CONCURRENT" &

sleep 3

AGENT_PORT=${AGENT_PORT:-5000}

echo ""
echo "=========================================="
echo "[+] Agent Running"
echo "=========================================="
echo ""
echo "Agent URL: http://$SERVER_IP:$AGENT_PORT"
echo "API Token: $API_TOKEN"
echo ""

ENCODED=$(python3 -c "
import base64, json
d = {'name':'$AGENT_NAME','url':'http://$SERVER_IP:$AGENT_PORT','api_key':'$API_TOKEN','max_concurrency':$MAX_CONCURRENT}
print('sqlmapagent://' + base64.b64encode(json.dumps(d).encode()).decode())
")

echo "Copy the following link to register this agent:"
echo "$ENCODED"
echo ""

wait
