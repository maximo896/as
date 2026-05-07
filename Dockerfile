FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir sqlmap flask requests

WORKDIR /app

COPY sqlmap_agent.py .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

EXPOSE 5000-60000

ENTRYPOINT ["./entrypoint.sh"]
