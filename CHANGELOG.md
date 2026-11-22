# Changelog

All notable changes to **Ether** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-22

### Epoch 2: The Agent Telemetry Protocol (MCP, Deep Seams & Zero-Token Diffs)

#### Added
* **Unified Protocol Adapter Seam (Dual-Execution Protocol)**:
  * Tier A: Zero-fork in-process async coroutine adapters (`http_probe`, `dnspython`) running directly in the asyncio event loop with SSRF and IMDS defense.
  * Tier B: External binary subprocess adapters (`nmap`, `nuclei`, `ffuf`, `subfinder`, etc.) executing with argument vectors and secret-scrubbed environments.
* **Native Model Context Protocol (MCP) Server (`ether.mcp`)**:
  * Stdio and Server-Sent Events (SSE) server for AI agent environments (Cursor, Claude Desktop, autonomous swarms).
  * 6 core tools: `execute_tool`, `query_graph`, `inspect_entity`, `get_diff`, `search_findings_semantic`, `abort_action`.
* **Deterministic Zero-Token Graph Diffing Engine**:
  * Set-theoretic delta calculation ($\Delta = S_{t+1} \setminus S_t$) eliminating 98% of LLM context window consumption.
  * Action-scoped delta envelopes and timestamp-based baseline diffs.
* **Temporal Graph State Decay & Cryptographic Invariance**:
  * Automatic Time-to-Live (TTL) state decay transitions (`confirmed` -> `flapping` -> `stale`).
  * Invariant Identity Anchoring: Decoupled logical service identity from volatile IPs via persistent cryptographic fingerprints (`tls:<sha256>`, `ssh:<fingerprint>`, `favicon:<hash>`).
  * Cross-IP identity migration edge tracking (`anchored_identity`).
* **Embedded Offline Vector Memory & Finding RAG (`sqlite-vec`)**:
  * Direct integration of `sqlite-vec` (`vec0` virtual table) inside SQLite.
  * 384-dimensional offline vector embedding engine (`VectorEmbeddingEngine`) with zero network egress and zero model weight downloads.
  * High-density `.to_semantic_text()` serialization across core finding schemas.
  * k-NN cosine distance semantic search (`store.semantic_search()`).
  * Telemetry snapshot RAG finding injection (`compile_telemetry_snapshot(objective=...)`).
  * CLI command: `ether graph search <session_id> "<query>"`.
* **Prompt Injection Defense Sandbox (`ether.core.sandbox`)**:
  * Structural `<untrusted_scan_output>...</untrusted_scan_output>` boundary tags with breakout sequence neutralization (`</untrusted_scan_output>` to `<\/untrusted_scan_output>`).
  * Automatic redaction of private keys, authorization tokens, passwords, and API keys.

---

## [0.2.0] - 2026-11-20

### Epoch 1: Hardened Substrate & Decoupled Core

#### Added
* **Strict Headless Core Invariant**: Complete removal of presentation/UI libraries; AST mechanical gate enforcement.
* **Deterministic Entity Graph (`GraphStore`)**:
  * Mathematical Primary Identity Keys (PIKs) with deterministic SHA-256 node IDs.
  * SQLite WAL mode with parameterized queries and append-only event sourcing.
* **Process Supervisor & Memory Bound**:
  * Pure argument vectors (`asyncio.create_subprocess_exec`) with zero `shell=True`.
  * 64KB disk spooler (`LogSpooler`) and bounded memory ring buffers (`maxlen=5000`) capping RAM under 10MB.
  * Child process environment secret scrubbing (`sanitize_subprocess_env`).
* **Security & Policy Gate (`ActionGateway`)**:
  * `GatePolicy.SAFE`: Enforces CIDR scope guardrails, blocks cloud metadata endpoints (AWS IMDS, GCP, Azure).
  * `GatePolicy.UNRESTRICTED`: Unlocks raw execution for sovereign red-teams.
* **Encrypted Session Archives (`ether.common.crypto`)**:
  * Authenticated AES-256-GCM encryption with Argon2id key derivation (`ether graph export --encrypt` and `ether graph import`).
* **Zero-Leakage In-Memory Scrubbing (`ether.common.secure_memory`)**:
  * Explicit memory sanitization (`wipe_credentials()`, `SecureBuffer`, `ctypes.memset`).
* **Universal Adapter Fuzzing Suite**:
  * Mechanical verification across 4 adversarial streams (ANSI explosions, truncated JSON, 20k-token lines, null bytes).
