# Multi-arch compatible Debian image for headless Ether security engine
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Ether" \
      org.opencontainers.image.description="Reactive Telemetry & Process Supervisor Substrate for Cybersecurity Tooling & Autonomous AI Agents" \
      org.opencontainers.image.url="https://github.com/h45sh/ether" \
      org.opencontainers.image.source="https://github.com/h45sh/ether"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    ETHER_DATA_DIR=/root/.ether

# Install core security tools supervised by Ether
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gobuster \
    whois \
    ffuf \
    sqlmap \
    perl \
    libxml-writer-perl \
    ca-certificates \
    curl \
    git \
    tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY tools/ ./tools/

# Install ether
RUN pip install --no-cache-dir .

# Default headless entrypoint
ENTRYPOINT ["python3", "-m", "ether"]
