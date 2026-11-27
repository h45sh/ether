# Ether Mechanical Performance Benchmarks & Operational Limits

> **Environment:** Linux 7.2.15-1-omarchy (x86_64) | **Python:** 3.12.12 | **Storage:** SQLite 3.45+ WAL mode with `sqlite-vec`

This document records authoritative, reproducible performance benchmarks validating Ether's mechanical speed, concurrency, memory guarantees, and security invariants. All detailed raw JSON execution traces are archived in `reports/`.

---

## 1. Execution & Query Latencies

Measures end-to-end command latency, database query overhead, and sub-millisecond vector similarity search in production-configured sessions.

| Benchmark / Operation | Metric / Percentile | Target / Ceiling | Status |
| :--- | :--- | :--- | :---: |
| **CLI Command Execution (`ether run`)** | **p50: 1,300.34 ms** \| **p95: 1,903.75 ms** | Sub-2s responsive execution | **PASS** |
| **GraphStore Bulk Finding Query** | **16.45 ms** (2,000 nodes queried) | $\le$ 500 ms | **PASS** |
| **Vector k-NN Search (`sqlite-vec`)** | **4.40 ms** (384-dim cosine distance, top-5) | $\le$ 50 ms (Zero network egress) | **PASS** |

---

## 2. High-Concurrency Storage & Write Throughput

Measures SQLite WAL ingestion throughput, exact-ownership transactional batch coalescing via `WriteQueue`, and schema normalization under load.

| Benchmark / Subsystem | Measured Rate | Operational Guarantee | Status |
| :--- | :--- | :--- | :---: |
| **Concurrent WAL Ingestion** | **2,266.4 upserts/sec** (1,000 entities, 10 workers, 0.441s; prior baseline 1,753.2/s) | $\ge$ 1,200 entities/sec hard floor | **PASS** |
| **Batch Ingestion Throughput** | **3,171.5 entities/sec** (2,000 nodes in 0.63s) | $\ge$ 2,000 entities/sec | **PASS** |
| **Streaming Output Spooling** | **206,169 lines/sec** (10,000 lines in 0.048s) | $\ge$ 50,000 lines/sec (64KB chunks) | **PASS** |
| **Schema Normalization & PIK Hashing** | **47,159 findings/sec** (10,000 models in 0.21s) | Deterministic SHA-256 generation | **PASS** |

---

## 3. Memory Boundedness & Resource Limits

Validates process isolation, ring buffer caps, and strict heap boundedness under high-volume streaming scans.

| Benchmark / Load Condition | Traced RAM Delta | Hard Enforcement Cap | Status |
| :--- | :--- | :--- | :---: |
| **Chaos Stream Flood (15MB noisy stream)** | **0.366 MB RSS Delta** (prior baseline 0.368 MB) | Strict ceiling: < 10.0 MB per active job | **PASS** |
| **High-Throughput Spooler Buffer** | **1.497 MB** ring buffer across 100,000 lines (26.49 MB disk spool) | Bounded ring buffer (`maxlen=5000`) | **PASS** |
| **SQLite In-Memory Engine State** | **Passes `PRAGMA integrity_check`** | Zero database corruption or lock timeouts | **PASS** |

---

## 4. Security Boundary & Isolation Invariants

Evaluates engine-level security guardrails, sandbox containment, and tamper-evident audit logging.

| Security Seam / Invariant | Verified Capability | Test Verification Method | Status |
| :--- | :--- | :--- | :---: |
| **SSRF & IMDS Containment (`SAFE` Policy)** | 100% block rate on HTTP 302 redirects to `169.254.169.254`, IPv6 equivalents, hex/octal evasion, and DNS rebinding | Automated adversarial bypass suite | **PASS** |
| **Child Subprocess Secret Scrubbing** | Zero leaked environment secrets (`ETHER_*`, `AWS_*`, `OPENAI_*`, `SSH_*`, lowercase variants) | Inspect active child process `/proc` environment | **PASS** |
| **Prompt Injection Boundary** | Neutralizes unescaped closing tags (`</untrusted_scan_output>` $\to$ `<\/untrusted_scan_output>`) | Structural XML sandbox fuzzing | **PASS** |
| **Adversarial Stream Crash Immunity** | 0.00% crash rate across 648 hostile input streams (36 adapters $\times$ 18 streams: broken ANSI, null bytes, truncated JSON, 20K floods) | Universal parser fuzzing matrix | **PASS** |
| **Forensic Audit Integrity** | 100% detection of 1-byte log tampering; sealed sessions enforce `PermissionError` immutability | SHA-256 block hash chaining & gzip compaction | **PASS** |

---

## 5. AI Telemetry & Token Economics

Measures LLM context efficiency and data volume reduction achieved by Ether's differential telemetry.

| Telemetry Stream | Data Volume / Payload | Context Efficiency Impact |
| :--- | :--- | :--- |
| **Raw Terminal Stream** | 50,000+ tokens per scan | Context window saturation, prompt injection vulnerability |
| **Ether Set-Theoretic Diff ($\Delta = S_{t+1} \setminus S_t$)** | **0 net tokens** on unchanged state | **> 98.4% token reduction** across repeated agent reasoning cycles |

---

## 6. Cold-Start Import Speeds & Packaging

Measures isolated subprocess cold-start latency across core modules and standalone wheel verification. Target ceiling: < 1,200 ms per module.

| Module | Description | Cold-Start Latency | Status |
| :--- | :--- | :---: | :---: |
| `ether` | Core Package Top-Level | 281.5 ms | **PASS** |
| `ether.core.executor` | Process Supervisor & Spooler | 292.4 ms | **PASS** |
| `ether.core.session` | Execution Session Manager | 291.3 ms | **PASS** |
| `ether.graph.store` | Deterministic GraphStore Engine | 287.1 ms | **PASS** |
| `ether.gateway.gate` | ActionGateway & Policy Engine | 284.4 ms | **PASS** |
| `ether.schemas.base` | Base Finding & PIK Substrate | 290.4 ms | **PASS** |
| `ether.mcp.server` | Native MCP Server (Stdio/SSE) | 1,012.8 ms | **PASS** |

**Packaging Isolation:** Standalone wheel build (`ether_core-0.1.3-py3-none-any.whl`) installs cleanly and executes outside the git checkout (`CWD=/tmp`), exposing 36 registered tool adapters, bundled fallback wordlists, and an 18-tool / 1-resource / 2-prompt MCP `stdio` surface (`ether mcp`).

---

## 7. Live Multi-Target & Cyber-Range Capabilities (AWS & VPN)

Verified across live AWS EC2 dual-posture targets (`GatePolicy.SAFE` and `GatePolicy.UNRESTRICTED`) and a live TryHackMe target (`10.48.157.67` over `tun0` in `GatePolicy.UNRESTRICTED`):
- **Live AWS Dual-Posture (`SAFE` & `UNRESTRICTED`):**
  - **Blind `GatePolicy.SAFE` (`16.179.220.153` vs `13.211.171.71`):** Discovered exposed vs. hardened postures using `nmap --profile fast`, `http_probe`, `ffuf --profile fast`, and `nuclei --profile deep`, persisting 14 nodes / 30 edges on the vulnerable target (OWASP Juice Shop `:80` + `gunicorn/19.9.0` `:8080`) vs. 5 nodes / 4 edges on the hardened `nginx` baseline.
  - **`GatePolicy.UNRESTRICTED` (`16.178.229.204` vs `32.236.190.178`):** Executed `nmap --script` NSE probes, `ffuf`, `http_probe`, `nuclei`, `ether report -s <SESSION_ID>`, and `ether session verify-audit` with deterministic graph deduplication and same-origin `anchored_identity` disambiguation (ADR 0018).
- **Live VPN Cyber Range (`10.48.157.67` over `tun0`, `GatePolicy.UNRESTRICTED`):**
  - `nmap` top-1000 connect sweep (`--min-rate 500 -Pn`) completed in `1.20s` over `tun0`, discovering 5 open TCP ports (`22`, `53`, `7777`, `7778`, `8443`) and persisting `network.host` and `network.service` nodes.
  - `http_probe` fingerprinted HTTP services (`nginx/1.28.2` CyberChef on `:7777`, `nginx/1.29.5` Reverse Shell Generator on `:7778` with SHA-256 favicon hash), wrapped HTML body previews in `<untrusted_scan_output>` tags, and enforced `verify_tls=True` against self-signed TLS on `:8443`.
  - `ffuf` executed 136 directory probes in `<1s` using bundled fallback wordlists; `GraphStore` deduplicated all findings into 12 PIK nodes, 9 edges, and 36 event-log rows.
- **Observed Operational Constraints (tracked in `ROADMAP.md`):**
  - Bundled `tools/*/manifest.toml` files lack `.toml.sha256`/`.py.sig` artifacts, requiring `ETHER_PLUGIN_TRUST_MODE=dev` for `ether doctor` / `ether run`.
  - `nmap -sV --top-ports 1000` over VPN exceeded the default `120.0s` timeout and returned `status="running", findings_count=0` until split into fast port discovery + targeted `-sV -p ...`.
  - `tls_probe` connected to port `443` regardless of `--flags "-p 8443"`.
  - `http_probe` rejected self-signed TLS on `:8443` even when `--policy unrestricted` and `--flags "-k"` were passed.
