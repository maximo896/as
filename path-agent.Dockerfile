FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl git unzip ca-certificates && rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/opt/path-agent-venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
ENV PATH_AGENT_PYTHON="${VIRTUAL_ENV}/bin/python"

RUN python3 -m venv "${VIRTUAL_ENV}"

RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch

RUN "${VIRTUAL_ENV}/bin/pip" install --no-cache-dir --upgrade pip setuptools wheel \
    && "${VIRTUAL_ENV}/bin/pip" install --no-cache-dir flask requests beautifulsoup4 \
    && "${VIRTUAL_ENV}/bin/pip" install --no-cache-dir -r /opt/dirsearch/requirements.txt

RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists \
    && mkdir -p /opt/wordlists \
    && cat \
      /opt/seclists/Discovery/Web-Content/common.txt \
      /opt/seclists/Discovery/Web-Content/raft-small-directories.txt \
      /opt/seclists/Discovery/Web-Content/raft-small-files.txt \
      /opt/seclists/Discovery/Web-Content/Logins.fuzz.txt \
      /opt/seclists/Discovery/Web-Content/admin-panels.txt \
      /opt/dirsearch/db/dicc.txt \
      | sed 's/\r$//' \
      | sed '/^\s*$/d' \
      | sed '/^\s*#/d' \
      | sed '/^\s*\/\//d' \
      | sort -u > /opt/wordlists/path-default.txt \
    && rm -rf /opt/seclists

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) katana_arch="amd64" ;; \
        arm64) katana_arch="arm64" ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    release_json="$(curl -fsSL https://api.github.com/repos/projectdiscovery/katana/releases/latest)"; \
    asset_url="$(printf '%s' "$release_json" | python3 -c "import json, sys; data = json.load(sys.stdin); arch = sys.argv[1]; suffix = f'linux_{arch}.zip'; print(next((asset['browser_download_url'] for asset in data.get('assets', []) if asset.get('name', '').endswith(suffix)), ''))" "$katana_arch")"; \
    test -n "$asset_url"; \
    curl -fsSL "$asset_url" -o /tmp/katana.zip; \
    unzip -q /tmp/katana.zip -d /tmp/katana; \
    install -m 0755 /tmp/katana/katana /usr/local/bin/katana; \
    rm -rf /tmp/katana /tmp/katana.zip

WORKDIR /app

COPY path_agent.py /app/path_agent.py
COPY path-agent-docker-entrypoint.sh /app/path-agent-docker-entrypoint.sh

RUN chmod +x /app/path-agent-docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/app/path-agent-docker-entrypoint.sh"]
