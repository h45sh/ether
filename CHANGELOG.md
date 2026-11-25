# Changelog

All notable changes to **Ether** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.4] - 2026-11-24

### Hardened Core, Sandbox Integrity & Forensic Telemetry Substrate (Epoch 3 Section 5)

#### Forensic Telemetry & Cryptographic Audit Trails
* **Cryptographic Hash Chaining (`ForensicLogManager`)**: Every supervised tool execution automatically appends an `AuditRecord` containing SHA-256 hashes of the action payload, raw output log file, previous audit record hash, and chained block hash.
* **Automatic Audit Compaction**: Session closure triggers automatic gzip compaction of uncompressed raw spool files into `{action_id}.log.gz` while verifying and updating SHA-256 hashes in the session audit manifest.
* **Audit Verification CLI**: Added `ether session verify-audit <SESSION_ID>` CLI subcommand to mechanically verify the cryptographic chain of custody and file integrity.

#### High-Fidelity Scanner Telemetry & Sandbox Integrity
* **Purge of Destructive Filters**: Completely purged `strip_scanner_noise()` and in-transit credential redaction (`redact_sensitive_artifacts()`). Tool output is preserved in high fidelity for vulnerability and credential discovery.
* **Bounded Context Framing**: Standardized `wrap_untrusted_output()` with a strict 100,000-character ceiling to prevent context window overflow while neutralizing XML closing tag breakout attacks (`<\/untrusted_scan_output>`).
* **Presentation-Time Credential Masking**: Implemented `--unmask` flag for CLI node inspection and search, preserving credentials in the graph while masking sensitive attributes by default in terminal output.

#### Deep Seam Gateway & Dynamic Preflight
* **Deep Scope Validation (`ScopeValidator`)**: Implemented high-performance CIDR containment and link-local/cloud metadata defense (`169.254.169.254`, `fd00:ec2::254`) using `RadixTrie` under `GatePolicy.SAFE`.
* **Dynamic Target Guidance**: Externalized static lookup tables in `preflight.py`; target guidance is dynamically synthesized from tool manifests, target schemas, and capability metadata.
* **5-Tier Wordlist Resolution (`AssetResolver`)**: Added hierarchical asset discovery supporting embedded minimal wordlists, system SecLists, user overrides, and prefix stripping (`@wordlist.txt`).

#### Architectural Decoupling & GraphStore Decomposition
* **Write Queue Worker (`WriteQueueWorker`)**: Extracted async serialization queue and adaptive transaction batch commit worker into a standalone module in `ether.graph.write_queue`.
* **Vector Index Engine (`VectorIndex`)**: Extracted `sqlite-vec` extension loading, virtual table maintenance, batch embeddings, and cosine similarity search into `ether.graph.vector_index`.
* **Zero Legacy Shims**: Purged `ActionGateway.neutralize_prompt()` and runtime schema migration DDL loops, adhering to the clean, fresh engine policy.

---

## [0.1.3] - 2026-11-23

### Supervisory Model Context Protocol (MCP) Expansion & Extreme Mechanical Constraints

#### Model Context Protocol (MCP)
* **Full 13-Tool Supervisory Interface**: Expanded MCP server from 6 to 13 first-class tools:
  * Graph intelligence tools: `get_attack_path` (Dijkstra shortest attack vector traversal), `get_blast_radius` (BFS multi-hop compromise impact analysis), `get_crown_jewels` (critical/high severity vulnerability indexing).
  * Environment inspection & adapter discovery: `list_tools`, `get_tool_info` (adapter execution tier, binary requirement, schema contract).
  * Session lifecycle & forensic log streaming: `manage_session` (workspace and session creation/listing), `read_action_log` (streaming sanitized stdout logs).
  * Tool execution timeout fallback: automatic background continuation without job killing when timeout elapses.

#### Engineering Constraints & Mechanical Hardening
* **Strict Static Typing**: Comprehensive MyPy strict type annotations across 56 source modules in `src/ether/`.
* **In-Tree AST Mutation Testing**: Implemented sub-second AST mutation engine (`tests/mutation/run_mutation_tests.py`) asserting 100% mutation kill score on core canonicalization and security boundary primitives.
* **Behavioral Scenario Contracts**: Golden lifecycle contracts verifying full recon-to-compromise ingestion, SHA-256 PIK deterministic invariance, idempotent upsert, and forensic session immutability (`PermissionError` on sealed sessions).
* **Package & PyPI Documentation Hardening**: Upgraded all relative links to absolute GitHub URLs in `README.md` to prevent broken links on the PyPI package page, and added comprehensive project URLs in `pyproject.toml`.

---

## [0.1.2] - 2026-11-23

### Bug Fixes
* **Graph Database Migration**: Avoid non-constant default `CURRENT_TIMESTAMP` in SQLite `ALTER TABLE ADD COLUMN` for backward compatibility on existing databases.

---

## [0.1.1] - 2026-11-23

### Features
* **Session & Graph Store Contracts**: Enhance session, graph store, and gateway contracts for external consumer integration.

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
  * `GatePolicy.UNRESTRICTED`: Unconstrained execution mode for authorized red-team engagements and advanced penetration testing operations.
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
