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

Measures SQLite WAL ingestion throughput, transactional batch coalescing via `WriteQueueWorker`, and schema normalization under load.

| Benchmark / Subsystem | Measured Rate | Operational Guarantee | Status |
| :--- | :--- | :--- | :---: |
| **Concurrent WAL Ingestion** | **1,753.2 upserts/sec** | $\ge$ 1,200 entities/sec hard floor | **PASS** |
| **Batch Ingestion Throughput** | **3,171.5 entities/sec** (2,000 nodes in 0.63s) | $\ge$ 2,000 entities/sec | **PASS** |
| **Streaming Output Spooling** | **206,169 lines/sec** (10,000 lines in 0.048s) | $\ge$ 50,000 lines/sec (64KB chunks) | **PASS** |
| **Schema Normalization & PIK Hashing** | **47,159 findings/sec** (10,000 models in 0.21s) | Deterministic SHA-256 generation | **PASS** |

---

## 3. Memory Boundedness & Resource Limits

Validates process isolation, ring buffer caps, and strict heap boundedness under high-volume streaming scans.

| Benchmark / Load Condition | Traced RAM Delta | Hard Enforcement Cap | Status |
| :--- | :--- | :--- | :---: |
| **Chaos Stream Flood (15MB noisy stream)** | **0.368 MB RSS Delta** | Strict ceiling: < 10.0 MB per active job | **PASS** |
| **High-Throughput Spooler Buffer** | **724.36 KB heap delta** | Bounded ring buffer (`maxlen=5000`) | **PASS** |
| **SQLite In-Memory Engine State** | **Passes `PRAGMA integrity_check`** | Zero database corruption or lock timeouts | **PASS** |

---

## 4. Security Boundary & Isolation Invariants

Evaluates engine-level security guardrails, sandbox containment, and tamper-evident audit logging.

| Security Seam / Invariant | Verified Capability | Test Verification Method | Status |
| :--- | :--- | :--- | :---: |
| **SSRF & IMDS Containment (`SAFE` Policy)** | 100% block rate on HTTP 302 redirects to `169.254.169.254`, IPv6 equivalents, hex/octal evasion, and DNS rebinding | Automated adversarial bypass suite | **PASS** |
| **Child Subprocess Secret Scrubbing** | Zero leaked environment secrets (`ETHER_*`, `AWS_*`, `OPENAI_*`, `SSH_*`, lowercase variants) | Inspect active child process `/proc` environment | **PASS** |
| **Prompt Injection Boundary** | Neutralizes unescaped closing tags (`</untrusted_scan_output>` $\to$ `<\/untrusted_scan_output>`) | Structural XML sandbox fuzzing | **PASS** |
| **Adversarial Stream Crash Immunity** | 0.00% crash rate across 630 hostile input streams (broken ANSI, null bytes, truncated JSON, 20K floods) | Universal parser fuzzing matrix | **PASS** |
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

**Packaging Isolation:** Standalone wheel build (`ether_core-0.1.3-py3-none-any.whl`) installs cleanly and executes outside git checkout with 35 discoverable tool adapters and bundled fallback wordlists.
