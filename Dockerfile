# Multi-arch compatible Debian image for headless Ether security engine
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Ether" \
      org.opencontainers.image.description="Reactive Telemetry & Process Supervisor Substrate for Cybersecurity Tooling & Autonomous AI Agents" \
      org.opencontainers.image.url="https://github.com/h45sh/ether" \
      org.opencontainers.image.source="https://github.com/h45sh/ether"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    ETHER_DATA_DIR=/home/ether/.ether

# Install core security tools supervised by Ether:
# - nmap, gobuster, whois, ffuf, sqlmap: standard CLI tool adapters
# - libxml-writer-perl: required by nikto for XML report output
# - libcap2-bin: provides setcap for granting fine-grained Linux capabilities to scanners
# - ca-certificates, curl, unzip, git, tar: required for binary extraction and tool setup
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gobuster \
    whois \
    ffuf \
    sqlmap \
    perl \
    libnet-ssleay-perl \
    libxml-writer-perl \
    libcap2-bin \
    ca-certificates \
    curl \
    unzip \
    tar \
    git \
    && git init /opt/nikto \
    && git -C /opt/nikto fetch --depth 1 https://github.com/sullo/nikto.git 312645d873478a77986627ab1fc8cffe595e85d4 \
    && git -C /opt/nikto checkout --detach FETCH_HEAD \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && git init /opt/exploitdb \
    && git -C /opt/exploitdb fetch --depth 1 https://gitlab.com/exploit-database/exploitdb.git 8a926a9b85beb3bccd6e8016211fdb73e904b52b \
    && git -C /opt/exploitdb checkout --detach FETCH_HEAD \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# Install subfinder binary from official ProjectDiscovery release (multi-arch)
ARG SUBFINDER_VERSION=2.6.6
RUN ARCH="$(dpkg --print-architecture)" && \
    case "${ARCH}" in \
        amd64) SUBFINDER_ARCH="amd64" ;; \
        arm64) SUBFINDER_ARCH="arm64" ;; \
        *) echo "Unsupported architecture for subfinder: ${ARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${SUBFINDER_ARCH}.zip" -o /tmp/subfinder.zip && \
    unzip -q /tmp/subfinder.zip -d /tmp/subfinder_bin && \
    mv /tmp/subfinder_bin/subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder*

# Install nuclei binary from official ProjectDiscovery release (multi-arch)
ARG NUCLEI_VERSION=3.3.7
RUN ARCH="$(dpkg --print-architecture)" && \
    case "${ARCH}" in \
        amd64) NUCLEI_ARCH="amd64" ;; \
        arm64) NUCLEI_ARCH="arm64" ;; \
        *) echo "Unsupported architecture for nuclei: ${ARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin && \
    mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei*

# Create unprivileged system user/group (UID/GID 1000) with home directory
RUN groupadd -g 1000 ether && \
    useradd -u 1000 -g ether -m -s /bin/bash ether && \
    mkdir -p /home/ether/.ether && \
    chmod 700 /home/ether/.ether && \
    chown -R ether:ether /home/ether

WORKDIR /app

# Copy packaging manifests, source code, and bundled assets
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY tools/ ./tools/

# Install ether package in container
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Create persistent storage directory for session graphs and telemetry logs
VOLUME ["/home/ether/.ether"]

WORKDIR /home/ether
USER ether

# Default headless entrypoint
ENTRYPOINT ["python3", "-m", "ether"]
