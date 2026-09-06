# ── Build image for Gemini Spark Terminal MCP Server ──────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# System packages
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    curl wget git vim nano \
    iputils-ping net-tools dnsutils \
    nodejs npm \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Working dir
WORKDIR /app
RUN mkdir -p /app/downloads /app/temp

# Python deps
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# App code
COPY server.py .

EXPOSE 8080

CMD ["python3", "-u", "server.py"]
