FROM golang:1.24 AS sqlmapsh-builder

WORKDIR /src

COPY sqlmapsh_agent/go.mod /src/go.mod
COPY sqlmapsh_agent/main.go /src/main.go

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/sqlmapsh-agent ./main.go

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir sqlmap flask requests

WORKDIR /app

COPY sqlmap_agent.py /app/sqlmap_agent.py
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
COPY sqlmap_hooks /opt/sqlmap-hooks
COPY --from=sqlmapsh-builder /out/sqlmapsh-agent /usr/local/bin/sqlmapsh-agent

RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
