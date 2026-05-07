#!/bin/bash
set -e

while getopts "n:p:c:" opt; do
  case $opt in
    n) AGENT_NAME="$OPTARG" ;;
    p) AGENT_PORT="$OPTARG" ;;
    c) MAX_CONCURRENT="$OPTARG" ;;
  esac
done

AGENT_NAME="${AGENT_NAME:-agent}"
AGENT_PORT="${AGENT_PORT:-5000}"
MAX_CONCURRENT="${MAX_CONCURRENT:-10}"

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

TMP=$(mktemp -d)
curl -fsSL https://github.com/maximo896/as/archive/refs/heads/main.tar.gz | tar xz -C "$TMP" --strip-components=1

PUBLIC_HOST=$(curl -fsSL https://api.ipify.org 2>/dev/null || true)
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST=$(hostname -I | awk '{print $1}')
fi

IMAGE=sqlmap-agent:latest
docker build -t "$IMAGE" "$TMP"

CN="sqlmap-agent-${AGENT_NAME}"
docker rm -f "$CN" >/dev/null 2>&1 || true

docker run -d \
  --name "$CN" \
  -p "${AGENT_PORT}:5000" \
  -e AGENT_NAME="$AGENT_NAME" \
  -e MAX_CONCURRENT="$MAX_CONCURRENT" \
  -e PUBLIC_HOST="$PUBLIC_HOST" \
  -e HOST_PORT="$AGENT_PORT" \
  --restart always \
  "$IMAGE" >/dev/null

sleep 3
docker logs --tail 50 "$CN"
