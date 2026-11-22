# Changelog

All notable changes to **Ether** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-22

### Initial Release: Headless Process Supervisor & Agent Telemetry Protocol

#### Core Engine & Process Supervision
* **Strict Headless Invariant**: Pure reactive execution substrate with zero UI dependencies, zero Textual imports, and automated AST mechanical gate verification.
* **Process Supervisor & Memory Governor**:
  * Pure argument vectors (`asyncio.create_subprocess_exec`) with zero `shell=True` (command injection immune).
  * 64KB log disk spooler (`LogSpooler`) and bounded in-memory ring buffers (`maxlen=5000`) strictly capping RAM under 10MB per active job.
  * Child process environment secret scrubbing (`sanitize_subprocess_env`) stripping host API keys and tokens.
* **Dual Security Policy Seam (`GatePolicy`)**:
  * `GatePolicy.SAFE`: Enforces CIDR scope boundaries, blocks link-local and cloud metadata endpoints (AWS IMDSv2, GCP, Azure).
  * `GatePolicy.UNRESTRICTED`: Unconstrained execution mode ("Beast Mode") for sovereign red-teams and offensive cyber warfare operations.
* **Prompt Injection Defense Sandbox (`ether.core.sandbox`)**:
  * Structural `<untrusted_scan_output>...</untrusted_scan_output>` boundary tags with breakout neutralization (`</untrusted_scan_output>` escaped to `<\/untrusted_scan_output>`).
  * Automatic redaction of private keys, authorization tokens, passwords, and API keys.

#### Deterministic Graph & Telemetry Engine
* **Deterministic Primary Identity Keys (PIK)**:
  * Entities (Hosts, Services, Vulnerabilities, Endpoints) identified by deterministic SHA-256 node IDs ($H(\text{schema} + \text{sorted\_pik})$).
  * Non-destructive idempotent upsert and relational graph wiring in SQLite WAL mode.
* **Temporal State Decay & Invariant Identity Anchoring**:
  * State confidence decay transitions (`confirmed` -> `flapping` -> `stale`) based on observation timestamps.
  * Decoupled logical service identity from volatile IPs via persistent cryptographic fingerprints (`tls:<sha256>`, `ssh:<fingerprint>`, `favicon:<hash>`).
  * Automatic cross-IP identity migration edge tracking (`anchored_identity`).
* **Zero-Egress Vector Memory & Finding RAG (`sqlite-vec`)**:
  * Native 384-dimensional offline vector embedding engine (`VectorEmbeddingEngine`) with zero network egress and zero model weight downloads.
  * Sub-millisecond k-NN semantic search and token-budgeted finding RAG injection.
* **Zero-Token Graph Diffing**:
  * Set-theoretic delta calculation ($\Delta = S_{t+1} \setminus S_t$) eliminating 98% of LLM context window consumption.
* **Encrypted Forensic Session Archives**:
  * Authenticated AES-256-GCM encryption with Argon2id key derivation for session export and import.

#### Multi-Modal Interfaces & Tooling
* **Native Model Context Protocol (MCP) Server**: Stdio and SSE transports exposing 6 high-leverage tools (`execute_tool`, `query_graph`, `inspect_entity`, `get_diff`, `search_findings_semantic`, `abort_action`).
* **Headless CLI**: 8 subcommands (`doctor`, `tool`, `run`, `session`, `graph`, `telemetry`, `logs`, `mcp`).
* **Universal Smart Adapters**: 12 pluggable adapters spanning subprocesses (Nmap, Nuclei, FFUF, Gobuster, Subfinder, Nikto, SQLmap, Searchsploit, Whois, NetExec) and native in-process async coroutines (DNSPython, HTTP Probe).
* **Multi-Arch OCI Container Image**: Ready-to-run Debian image preloaded with security tools (`ghcr.io/h45sh/ether:latest`).
* **Mechanical Verification Suite**: 284 passing tests, Tier 0 AST architectural gates, property-based tests, and universal adapter fuzzing.
