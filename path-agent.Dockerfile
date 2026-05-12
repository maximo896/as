FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl git golang-go ca-certificates && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask requests beautifulsoup4

RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch

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

RUN GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@latest

WORKDIR /app

COPY path_agent.py /app/path_agent.py
COPY path-agent-docker-entrypoint.sh /app/path-agent-docker-entrypoint.sh

RUN chmod +x /app/path-agent-docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/app/path-agent-docker-entrypoint.sh"]
