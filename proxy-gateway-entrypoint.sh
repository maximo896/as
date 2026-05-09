#!/bin/bash
set -euo pipefail

while getopts "n:l:N:" opt; do
  case "$opt" in
    n) AGENT_NAME="$OPTARG" ;;
    l) PROXY_AGENT_LINK="$OPTARG" ;;
    N) NETWORK_NAME="$OPTARG" ;;
  esac
done

AGENT_NAME="${AGENT_NAME:-agent}"
PROXY_AGENT_LINK="${PROXY_AGENT_LINK:-}"
NETWORK_NAME="${NETWORK_NAME:-}"

if [ -z "$PROXY_AGENT_LINK" ]; then
  echo "missing -l <proxy_agent_link>"
  exit 1
fi

sanitize_name() {
  local n
  n="$(echo "$1" | tr -cs 'a-zA-Z0-9._-' '-' | sed 's/^[._-]*//; s/[._-]*$//' | tr 'A-Z' 'a-z')"
  if [ -z "$n" ]; then
    n="agent"
  fi
  echo "$n"
}

SAFE_NAME="$(sanitize_name "$AGENT_NAME")"
SQLMAP_CN="sqlmap-agent-${SAFE_NAME}"
GATEWAY_CN="proxy-gateway-${SAFE_NAME}"
NETWORK_NAME="${NETWORK_NAME:-scan-net-${SAFE_NAME}}"

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

scheme="${PROXY_AGENT_LINK%%://*}"
rest="${PROXY_AGENT_LINK#*://}"
rest="${rest%%#*}"
auth_host="${rest%%\?*}"
client="${auth_host%@*}"
host_port="${auth_host#*@}"
server_host="${host_port%:*}"
server_port="${host_port##*:}"

if [ -z "$client" ] || [ -z "$server_host" ] || [ -z "$server_port" ]; then
  echo "invalid proxy agent link"
  exit 1
fi

mkdir -p "/tmp/${GATEWAY_CN}"
CONFIG_PATH="/tmp/${GATEWAY_CN}/config.json"

if [ "$scheme" = "trojan" ]; then
cat > "$CONFIG_PATH" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "listen": "0.0.0.0", "port": 18080, "protocol": "http", "settings": {} },
    { "listen": "0.0.0.0", "port": 18081, "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "trojan",
      "settings": {
        "servers": [
          { "address": "${server_host}", "port": ${server_port}, "password": "${client}" }
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
    { "listen": "0.0.0.0", "port": 18080, "protocol": "http", "settings": {} },
    { "listen": "0.0.0.0", "port": 18081, "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${server_host}",
            "port": ${server_port},
            "users": [ { "id": "${client}", "encryption": "none" } ]
          }
        ]
      }
    }
  ]
}
JSON
fi

docker network create "$NETWORK_NAME" >/dev/null 2>&1 || true
docker network connect "$NETWORK_NAME" "$SQLMAP_CN" >/dev/null 2>&1 || true
docker rm -f "$GATEWAY_CN" >/dev/null 2>&1 || true

docker run -d \
  --name "$GATEWAY_CN" \
  --network "$NETWORK_NAME" \
  --restart always \
  -v "$CONFIG_PATH:/etc/xray/config.json" \
  ghcr.io/xtls/xray-core:latest run -config /etc/xray/config.json >/dev/null

echo "proxy gateway started: ${GATEWAY_CN}"
echo "proxy url for sqlmap: http://${GATEWAY_CN}:18080"
