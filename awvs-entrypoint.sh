#!/bin/bash
set -euo pipefail

while getopts "n:p:c:" opt; do
  case "$opt" in
    n) AGENT_NAME="$OPTARG" ;;
    p) AGENT_PORT="$OPTARG" ;;
    c) MAX_CONCURRENT="$OPTARG" ;;
  esac
done

AGENT_NAME="${AGENT_NAME:-awvs}"
AGENT_PORT="${AGENT_PORT:-$((30000 + RANDOM % 10001))}"
MAX_CONCURRENT="${MAX_CONCURRENT:-5}"
AWVS_EMAIL="admin@admin.com"
AWVS_PASSWORD="Admin123"
AWVS_CONTAINER_PORT="3443"
IMAGE="secfa/awvs:latest"
CONTAINER_NAME="awvs-agent-${AGENT_NAME}"

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi

ensure_packages() {
  if ! command -v curl >/dev/null 2>&1; then
    $SUDO apt-get update
    $SUDO apt-get install -y curl
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    $SUDO apt-get update
    $SUDO apt-get install -y coreutils
  fi
}

install_docker() {
  for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    $SUDO apt-get remove -y "$pkg" >/dev/null 2>&1 || true
  done

  $SUDO apt-get update
  $SUDO apt-get install -y ca-certificates curl
  $SUDO install -m 0755 -d /etc/apt/keyrings
  $SUDO curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  $SUDO chmod a+r /etc/apt/keyrings/docker.asc

  ARCH="$(dpkg --print-architecture)"
  CODENAME="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${CODENAME} stable" | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
  $SUDO apt-get update
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    install_docker
  fi

  if ! $SUDO docker info >/dev/null 2>&1; then
    $SUDO systemctl start docker 2>/dev/null || $SUDO service docker start 2>/dev/null || true
  fi

  if ! $SUDO docker info >/dev/null 2>&1; then
    echo "docker not ready"
    exit 1
  fi
}

extract_json_value() {
  local key="$1"
  local file="$2"
  tr -d '\n' < "$file" | sed -n "s/.*\"${key}\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"
}

login_awvs() {
  local base_url="$1"
  local workdir="$2"
  local password_hash

  password_hash="$(printf '%s' "$AWVS_PASSWORD" | sha256sum | awk '{print $1}')"
  printf '{"email":"%s","password":"%s"}' "$AWVS_EMAIL" "$password_hash" > "${workdir}/login.json"

  curl -k -sS -D "${workdir}/login.headers" -c "${workdir}/cookies.txt" \
    -H 'Content-Type: application/json' \
    -X POST "${base_url}/api/v1/me/login" \
    --data-binary @"${workdir}/login.json" >/dev/null

  awk -F': ' 'BEGIN{IGNORECASE=1} /^X-Auth:/ {gsub("\r","",$2); print $2}' "${workdir}/login.headers" | tail -n 1
}

graphql_request() {
  local base_url="$1"
  local auth_token="$2"
  local workdir="$3"
  local body_file="$4"
  local out_file="$5"

  curl -k -sS -b "${workdir}/cookies.txt" \
    -H "X-Auth: ${auth_token}" \
    -H 'Content-Type: application/json' \
    -X POST "${base_url}/graphql/" \
    --data-binary @"${body_file}" > "${out_file}"
}

wait_for_awvs() {
  local base_url="$1"
  local attempts=120

  echo "[*] Waiting for AWVS to become ready..."
  for _ in $(seq 1 "$attempts"); do
    code="$(curl -k -s -o /dev/null -w '%{http_code}' "${base_url}/" || true)"
    if [ "$code" = "200" ]; then
      return 0
    fi
    sleep 10
  done

  echo "AWVS did not become ready in time"
  exit 1
}

build_protocol() {
  local name="$1"
  local url="$2"
  local api_key="$3"
  local max_concurrency="$4"
  local json

  json="$(printf '{"name":"%s","url":"%s","api_key":"%s","max_concurrency":%s}' "$name" "$url" "$api_key" "$max_concurrency")"
  printf 'awvsagent://%s\n' "$(printf '%s' "$json" | base64 | tr -d '\n')"
}

ensure_packages
ensure_docker

PUBLIC_HOST="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(hostname -I | awk '{print $1}')"
fi

$SUDO docker pull "$IMAGE" >/dev/null
$SUDO docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
$SUDO docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${AGENT_PORT}:${AWVS_CONTAINER_PORT}" \
  --cap-add LINUX_IMMUTABLE \
  --restart always \
  "$IMAGE" >/dev/null

BASE_URL="https://${PUBLIC_HOST}:${AGENT_PORT}"
LOCAL_URL="https://127.0.0.1:${AGENT_PORT}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

wait_for_awvs "$LOCAL_URL"

SESSION_TOKEN="$(login_awvs "$LOCAL_URL" "$WORKDIR")"
if [ -z "$SESSION_TOKEN" ]; then
  echo "failed to obtain awvs session token"
  exit 1
fi

printf '{"operationName":"apiKey","variables":{},"query":"query apiKey {\n  apiKey\n}"}' > "${WORKDIR}/query_api_key.json"
graphql_request "$LOCAL_URL" "$SESSION_TOKEN" "$WORKDIR" "${WORKDIR}/query_api_key.json" "${WORKDIR}/api_key.json"
API_KEY="$(extract_json_value "apiKey" "${WORKDIR}/api_key.json")"

if [ -z "$API_KEY" ] || [ "$API_KEY" = "null" ]; then
  printf '{"operationName":"generateApiKey","variables":{},"query":"mutation generateApiKey {\n  generateApiKey\n}"}' > "${WORKDIR}/generate_api_key.json"
  graphql_request "$LOCAL_URL" "$SESSION_TOKEN" "$WORKDIR" "${WORKDIR}/generate_api_key.json" "${WORKDIR}/generated_api_key.json"
  API_KEY="$(extract_json_value "generateApiKey" "${WORKDIR}/generated_api_key.json")"
fi

if [ -z "$API_KEY" ]; then
  echo "failed to obtain awvs api key"
  exit 1
fi

echo ""
echo "=========================================="
echo "[+] AWVS Installation Complete"
echo "=========================================="
echo "URL: ${BASE_URL}"
echo "Username: ${AWVS_EMAIL}"
echo "Password: ${AWVS_PASSWORD}"
echo ""
build_protocol "$AGENT_NAME" "$BASE_URL" "$API_KEY" "$MAX_CONCURRENT"
