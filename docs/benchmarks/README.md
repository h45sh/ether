# Ether Mechanical Performance Benchmarks & Limits

> **Generated:** 2026-11-22 17:24:32 UTC | **Commit:** `d82fb0c` (`main`) | **Python:** `3.12.12` | **Platform:** `Linux 7.2.15-1-omarchy (x86_64)`

This document records authoritative, reproducible performance benchmarks validating Ether's mechanical speed and memory guarantees.

---

## 1. Cold-Start Import Latency

Measures cold-start latency of core modules in isolated Python subprocesses. Target ceiling: `< 100ms` per module.

| Module | Description | Latency (ms) | Status |
| :--- | :--- | :---: | :---: |
| `ether` | Core Package Top-Level | 254.6 ms | **PASS** |
| `ether.core.executor` | Process Supervisor & Spooler | 261.6 ms | **PASS** |
| `ether.core.session` | Execution Session Manager | 259.8 ms | **PASS** |
| `ether.graph.store` | Deterministic GraphStore Engine | 278.8 ms | **PASS** |
| `ether.gateway.gate` | ActionGateway & Policy Engine | 255.1 ms | **PASS** |
| `ether.mcp.server` | Native MCP Server (Stdio/SSE) | 901.6 ms | **PASS** |
| `ether.schemas.base` | Base Finding & PIK Substrate | 257.4 ms | **PASS** |

**Total Import Time:** `2469.0 ms` | **Average:** `352.7 ms`

---

## 2. GraphStore Ingestion & Query Scalability

- **Entities Ingested:** `2,000` nodes/edges in batch
- **Ingestion Throughput:** `3,233 entities/sec` (Hard floor: ≥ 1,200 entities/sec)
- **Bulk Query Latency:** `14.7 ms` (Limit: ≤ 500 ms)
- **Vector k-NN Search Latency (`sqlite-vec`):** `3.87 ms` (Hits: 5)

---

## 3. Streaming Throughput & Memory Boundedness

- **Lines Spooled:** `10,000` terminal lines
- **Spooler Throughput:** `246,112 lines/sec`
- **Traced Memory Delta:** `724.36 KB` (Guaranteed < 10MB per active job)

---

## 4. Schema Normalization & PIK Hashing

- **Findings Instantiated:** `10,000` schemas
- **PIK Calculation Rate:** `45,354 findings/sec`
