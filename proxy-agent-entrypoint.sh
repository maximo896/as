#!/bin/bash
set -euo pipefail

while getopts "n:p:i:r:h:o:u:w:s:t:" opt; do
  case "$opt" in
    n) AGENT_NAME="$OPTARG" ;;
    p) LISTEN_PORT="$OPTARG" ;;
    i) CLIENT_ID="$OPTARG" ;;
    r) TUNNEL_PROTOCOL="$OPTARG" ;;
    h) TUNNEL_HOST="$OPTARG" ;;
    o) TUNNEL_PORT="$OPTARG" ;;
    u) TUNNEL_USERNAME="$OPTARG" ;;
    w) TUNNEL_PASSWORD="$OPTARG" ;;
    s) _IGNORED_SERVER_HOST="$OPTARG" ;;
    t) _IGNORED_TRANSPORT="$OPTARG" ;;
  esac
done

AGENT_NAME="${AGENT_NAME:-agent}"
LISTEN_PORT="${LISTEN_PORT:-443}"
CLIENT_ID="${CLIENT_ID:-}"
TUNNEL_PROTOCOL="${TUNNEL_PROTOCOL:-}"
TUNNEL_HOST="${TUNNEL_HOST:-}"
TUNNEL_PORT="${TUNNEL_PORT:-0}"
TUNNEL_USERNAME="${TUNNEL_USERNAME:-}"
TUNNEL_PASSWORD="${TUNNEL_PASSWORD:-}"
TRANSPORT="vless"

sanitize_name() {
  echo "$1" | tr -cs 'a-zA-Z0-9._-' '-'
}

new_uuid() {
  if [ -r /proc/sys/kernel/random/uuid ]; then
    cat /proc/sys/kernel/random/uuid
    return
  fi
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr 'A-Z' 'a-z'
    return
  fi
  python3 - <<'PY'
import uuid
print(str(uuid.uuid4()))
PY
}

is_uuid() {
  echo "$1" | grep -Eiq '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
}

if ! command -v curl >/dev/null 2>&1; then
  apt-get update && apt-get install -y curl
fi

SERVER_HOST="$(curl -fsSL ip.sb -4 2>/dev/null || true)"
if [ -z "$SERVER_HOST" ]; then
  SERVER_HOST="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
fi
if [ -z "$SERVER_HOST" ]; then
  SERVER_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
if [ -z "$SERVER_HOST" ]; then
  echo "failed to detect public ipv4"
  exit 1
fi

if [ -z "$CLIENT_ID" ] || ! is_uuid "$CLIENT_ID"; then
  CLIENT_ID="$(new_uuid)"
fi

case "$TUNNEL_PROTOCOL" in
  http|https|socks5|socks4a) ;;
  *)
    echo "unsupported tunnel protocol: $TUNNEL_PROTOCOL"
    exit 1
    ;;
esac

if [ -z "$TUNNEL_HOST" ] || [ "$TUNNEL_PORT" = "0" ]; then
  echo "missing -h <tunnel_host> or -o <tunnel_port>"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi

if ! docker info >/dev/null 2>&1; then
  systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker not ready"
  exit 1
fi

SAFE_NAME="$(sanitize_name "$AGENT_NAME")"
CONTAINER_NAME="proxy-agent-${SAFE_NAME}"
WORK_DIR="/tmp/${CONTAINER_NAME}"
CONFIG_PATH="${WORK_DIR}/config.json"

out_proto="socks"
if [ "$TUNNEL_PROTOCOL" = "http" ] || [ "$TUNNEL_PROTOCOL" = "https" ]; then
  out_proto="http"
fi

auth_block=""
if [ -n "$TUNNEL_USERNAME" ] || [ -n "$TUNNEL_PASSWORD" ]; then
  auth_block=", \"users\": [{\"user\": \"${TUNNEL_USERNAME}\", \"pass\": \"${TUNNEL_PASSWORD}\"}]"
fi

version_block=""
if [ "$TUNNEL_PROTOCOL" = "socks4a" ]; then
  version_block=", \"version\": 4"
fi

mkdir -p "$WORK_DIR"

cat > "$CONFIG_PATH" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${LISTEN_PORT},
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [{ "id": "${CLIENT_ID}" }]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "${out_proto}",
      "settings": {
        "servers": [
          {
            "address": "${TUNNEL_HOST}",
            "port": ${TUNNEL_PORT}${auth_block}${version_block}
          }
        ]
      }
    }
  ]
}
JSON

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart always \
  -p "${LISTEN_PORT}:${LISTEN_PORT}" \
  -v "$CONFIG_PATH:/etc/xray/config.json" \
  teddysun/xray >/dev/null

echo ""
echo "=========================================="
echo "[+] Proxy Agent Installation Complete!"
echo "=========================================="
echo "vless://${CLIENT_ID}@${SERVER_HOST}:${LISTEN_PORT}?encryption=none&type=tcp#${AGENT_NAME}"
