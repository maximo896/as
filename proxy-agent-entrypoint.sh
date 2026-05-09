#!/bin/bash
set -euo pipefail

while getopts "n:s:p:t:i:r:h:o:u:w:" opt; do
  case "$opt" in
    n) AGENT_NAME="$OPTARG" ;;
    s) SERVER_HOST="$OPTARG" ;;
    p) LISTEN_PORT="$OPTARG" ;;
    t) TRANSPORT="$OPTARG" ;;
    i) CLIENT_ID="$OPTARG" ;;
    r) TUNNEL_PROTOCOL="$OPTARG" ;;
    h) TUNNEL_HOST="$OPTARG" ;;
    o) TUNNEL_PORT="$OPTARG" ;;
    u) TUNNEL_USERNAME="$OPTARG" ;;
    w) TUNNEL_PASSWORD="$OPTARG" ;;
  esac
done

AGENT_NAME="${AGENT_NAME:-agent}"
SERVER_HOST="${SERVER_HOST:-}"
LISTEN_PORT="${LISTEN_PORT:-443}"
TRANSPORT="${TRANSPORT:-vless}"
CLIENT_ID="${CLIENT_ID:-}"
TUNNEL_PROTOCOL="${TUNNEL_PROTOCOL:-}"
TUNNEL_HOST="${TUNNEL_HOST:-}"
TUNNEL_PORT="${TUNNEL_PORT:-0}"
TUNNEL_USERNAME="${TUNNEL_USERNAME:-}"
TUNNEL_PASSWORD="${TUNNEL_PASSWORD:-}"

if [ -z "$SERVER_HOST" ]; then
  SERVER_HOST="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
fi
if [ -z "$SERVER_HOST" ]; then
  SERVER_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
if [ -z "$SERVER_HOST" ]; then
  echo "missing -s <server_host>"
  exit 1
fi

if [ -z "$CLIENT_ID" ]; then
  if command -v uuidgen >/dev/null 2>&1; then
    CLIENT_ID="$(uuidgen)"
  else
    CLIENT_ID="$(date +%s%N)"
  fi
fi

case "$TRANSPORT" in
  vless|trojan) ;;
  *)
    echo "unsupported transport: $TRANSPORT"
    exit 1
    ;;
esac

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

sanitize_name() {
  echo "$1" | tr -cs 'a-zA-Z0-9._-' '-'
}

if ! command -v curl >/dev/null 2>&1; then
  apt-get update && apt-get install -y curl
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

if [ "$TRANSPORT" = "trojan" ]; then
cat > "$CONFIG_PATH" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${LISTEN_PORT},
      "protocol": "trojan",
      "settings": {
        "clients": [{ "password": "${CLIENT_ID}" }]
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
else
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
fi

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
if [ "$TRANSPORT" = "trojan" ]; then
  echo "trojan://${CLIENT_ID}@${SERVER_HOST}:${LISTEN_PORT}#${AGENT_NAME}"
else
  echo "vless://${CLIENT_ID}@${SERVER_HOST}:${LISTEN_PORT}?encryption=none&type=tcp#${AGENT_NAME}"
fi
