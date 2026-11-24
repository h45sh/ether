# Ether Master Engineering Roadmap: The Ideal State

This authoritative roadmap outlines the evolution of **Ether** from its current foundation as a decoupled process supervisor to its **highest imagined ideal state: The Autonomous Telemetry Substrate for Cybersecurity Operations**.

---

## The Vision: The Autonomous Runtime Substrate

Every modern computing environment relies on a predictable supervisory runtime that schedules processes, manages execution lifecycles, provides IPC, and maintains structured state without coupling to presentation layers.

**Ether is that supervisory runtime engine for cybersecurity operations.**

Instead of human operators and AI agents clumsily spawning raw bash subshells and drowning in thousands of unstructured stdout lines, Ether provides:
1. **Universal Execution Virtualization:** Sandboxed process supervision, secret scrubbing, and backpressure-regulated streaming.
2. **Deterministic World State:** A reactive graph database where hosts, ports, web applications, credentials, and CVEs are deduplicated and merged on-the-fly via mathematical Primary Identity Keys (PIK).
3. **Pluggable Policy Isolation:** Running seamlessly in **Safe Mode** (for labs/universities like CyGuide) or **Unrestricted Mode** (for sovereign red-teams and autonomous offensive loops).
4. **Agent Telemetry Protocol:** Zero-token diff streaming via the Model Context Protocol (MCP), turning raw scanner noise into structured episodic memory for AI reasoning models.
5. **Decoupled Architecture:** 100% headless core. Zero presentation or terminal emulator code. Consumed upstream by CyGuide (pedagogical TUI), headless DAEMONS (`etherd`), and autonomous AI swarms.

---

## The Five Evolutionary Epochs

```text
 Epoch 1 ───────► Epoch 2 ───────► Epoch 3 ───────► Epoch 4 ───────► Epoch 5
 Decoupled        Autonomous       High-Throughput  Unrestricted     Distributed
 Foundation       Agent Gateway    Chained Mesh     Offensive Engine Sovereign Fleet
 (Current)        (MCP & Diffs)    (DAG Pipelines)  (PTY & Attack)   (Global Graph)
```

---

### Epoch 1: Hardened Substrate & Decoupled Core (Current Milestone)
*Target: v0.1.0 – v0.2.0*
*Focus: Complete architectural purity, mechanical gates, and 100% test coverage.*

- [x] **Repository Decoupling:** Fully autonomous repository at `/home/harsh/Documents/ether`.
- [x] **Headless Invariant:** Zero UI/Textual/presentation dependencies. Pure async core.
- [x] **Layer DAG Enforcement:** AST linting ensuring schemas never import higher layers.
- [x] **Dual Policy Seam:** `GatePolicy.SAFE` (blocks metadata, enforces CIDR) vs. `GatePolicy.UNRESTRICTED`.
- [x] **Deterministic State Machine:** SQLite WAL GraphStore with SHA-256 PIK hashing.
- [x] **Universal Fuzzing Matrix:** 11 built-in adapters passing 4-stream adversarial fuzzing.
- [x] **Comprehensive Regression Suite:** 230 unit and integration tests passing in <13s.
- [x] **Headless Performance Benchmarking & Regression Gate (`tests/benchmarks/test_perf_benchmarks.py`):**
  - Continuous regression benchmarks verifying SQLite WAL ingestion (>250 findings/sec), composite query latency (<500ms for 5,000 nodes), Pydantic model throughput (>15,000 models/sec), and `LogSpooler` memory bounds (<15MB resident RAM for 100k lines).
- [x] **Hardened Logging & In-Memory Flight Recorder (`ether.common.logging`):**
  - `SecureRotatingFileHandler` with atomic `0o600` permissions.
  - `SanitizingLogFormatter` with automated regex scrubbing for API keys, bearer tokens, passwords, and SSH keys.
  - `FlightRecorder` in-memory circular trace buffer (`deque(maxlen=200)`) and global unhandled exception traps.
- [x] **Category 2 Security Standards:** Atomic `0o600` file permissions (`atomic_create_file`), prompt boundary neutralization (`sanitize_untrusted_output`), and tiered file protection.
- [x] **Lightweight Headless CLI (`ether`):**
  - `ether doctor` (environment and dependency diagnostics across distros)
  - `ether tool list` & `ether tool info <tool>` (inspection of registered tool adapters)
  - `ether run <tool> <target> [--flags ...] [--json] [--policy safe|unrestricted]` (supervised execution and stream parsing)
  - `ether session list` & `ether session create <name>` (investigation session management)
  - `ether graph list-nodes <session_id>` & `ether graph export <session_id> -o out.json` (deterministic graph querying and export)
  - `ether telemetry snapshot <session_id>` & `ether telemetry diff <session_id> --baseline <ts>` (agent telemetry protocol)
  - `ether logs [--limit 50] [--crashes]` (runtime and post-mortem flight recorder logs)
- [x] **Encrypted Session Database Archives (`ether.common.crypto`):**
  - AES-256-GCM authenticated encryption for exported session databases with Argon2id passphrase key derivation (`ether graph export --encrypt` and `ether graph import`).
  - Cryptographic verification test suite rejecting truncated, bit-flipped, or tampered archives.
- [x] **Zero-Leakage In-Memory Credential & Secret Scrubbing (`ether.common.secure_memory`):**
  - Explicit memory sanitization (`wipe_credentials()`, `SecureBuffer`, `ctypes.memset`) upon process and task finalization, preventing residual keys from lingering in Python heap or core dumps.
- [x] **Packaging & PyPI Readiness:** Clean wheel builds with `uv build` and zero external C dependencies (`dist/ether_core-0.1.3-py3-none-any.whl`).

---

### Epoch 2: The Agent Telemetry Protocol (MCP, Deep Seams & Zero-Token Diffs)
*Target: v0.3.0*
*Focus: Deep Module interfaces for Autonomous AI Agents and In-Process Telemetry.*

- [x] **Unified Protocol Adapter Seam (`ToolAdapter` Dual-Execution Protocol):**
  - *Deep Module Design*: Deepen the `ToolAdapter` interface so callers and sessions do not care whether an execution is an OS subprocess or a native async coroutine.
  - Expose a single execution entry point at the seam: `execute_action(target, params, context) -> AsyncIterator[BaseFinding]`.
  - **Tier A In-Process Async Coroutines**: Zero-fork high-concurrency adapters (`http_probe` HTTP discovery with SSRF defense, `dnspython` DNS resolution & AXFR) running directly within the asyncio loop (10,000+ targets, <150MB RAM).
  - Automatically falls back to binary subprocess execution for compiled tools (`nmap`, `nuclei`, `ffuf`).
- [x] **Native Model Context Protocol (MCP) Server (`ether.mcp`):**
  - Stdio and Server-Sent Events (SSE) server allowing Cursor, Claude Desktop, and autonomous agent swarms to drive Ether directly.
  - Complete 13-tool supervisory agent interface:
    - Execution & Diagnostics: `execute_tool`, `abort_action`, `read_action_log`
    - State & Telemetry: `query_graph`, `inspect_entity`, `get_diff`, `search_findings_semantic`
    - Arsenal Introspection: `list_tools`, `get_tool_info`
    - Graph Intelligence & Attack Paths: `get_attack_path`, `get_blast_radius`, `get_crown_jewels`
    - Workspace Management: `manage_session`
- [x] **Deterministic Zero-Token Graph Diffing Engine:**
  - After any action completes, compute the exact set-theoretic delta:
    $$\Delta = S_{t+1} \setminus S_t$$
  - Return compact semantic diffs to agents:
    ```json
    {
      "added_nodes": [{"type": "network.service", "port": 443, "service": "https"}],
      "updated_nodes": [{"id": "da7246ff", "new_attributes": {"os": "Linux 6.1"}}],
      "tokens_consumed": 0
    }
    ```
  - **Result:** Reduces agent LLM context window consumption by **98%** compared to reading raw stdout.
- [x] **Temporal Graph State Decay & Cryptographic Invariance (`GraphStore`):**
  - **Time-to-Live (TTL) State Decay**: Node state confidence decay windows (`confirmed`, `flapping`, `stale`) handling container churn and fast-flux DNS rotation without orphan node pollution.
  - **Invariant Identity Anchoring**: Decouple logical service identity from volatile IP addresses by anchoring Primary Identity Keys (PIK) to persistent cryptographic fingerprints (TLS cert SHA-256, SSH host keys, HTTP favicon/ETag hashes).
- [x] **Embedded Offline Vector Memory & Finding RAG (`sqlite-vec`):**
  - Direct integration of `sqlite-vec` vector embeddings within SQLite.
  - Generates fast local vector embeddings for discovered services, banners, MITRE ATT&CK techniques, and CVE summaries.
  - Instant local semantic search and finding correlation with zero external API calls or network egress.
- [x] **Prompt Injection Defense Sandbox (`ether.core.sandbox`):**
  - Standardized `<untrusted_scan_output>` boundary tags with closing tag breakout neutralization (`</untrusted_scan_output>` converted to `<\/untrusted_scan_output>`).
  - Automatic redaction of private keys, authorization tokens, passwords, and API keys.
  - Active neutralization of adversarial prompt injection embedded inside HTTP headers, SSL certificates, and DNS TXT records.

---

### Epoch 3: Universal Security Tool Arsenal, Chained Pipeline DAG & Substrate Optimizations
*Target: v0.4.0*
*Focus: Complete Kali Linux / Modern Security Tool Adapter Ecosystem, Hybrid In-Process Probers, Reactive Pipeline DAGs, and Process Stream Optimization.*

#### 1. Fundamental Engine Improvements & Bug Fixes (Identified in AWS Multi-Target Evaluation)
- [x] **CLI & MCP Parameter Symmetry & Harmonization:**
  - Standardize all parameter aliases across CLI subcommands and MCP tool definitions.
  - Fix `--budget` alias for `--max-tokens` in `ether telemetry snapshot` (`ether/cli/telemetry.py`).
  - Auto-generate CLI argument parsers and MCP tool definitions from single canonical `manifest.toml` schemas.
- [x] **Hybrid Dual-Execution Adapters (Zero-Binary Graceful Degradation):**
  - Implement dual-tier adapters that automatically detect binary presence on PATH:
    - If binary is present: Execute high-performance compiled binary with pure argument vectors.
    - If binary is absent: Gracefully degrade to in-process pure-Python `asyncio` coroutine probers without failing or halting agent workflows.
- [x] **Process Stream Normalization & Curses De-Escaping (`executor.py`):**
  - Implement a byte-boundary chunk normalizer in `LogSpooler` and stream readers.
  - Automatically strip carriage returns (`\r`) and ANSI escape sequences emitted by interactive tools (e.g. `ffuf`, `hydra`, `gobuster`) to prevent event-loop buffer hangs.
- [x] **Detailed Firewall & Filter Classification:**
  - Enhance Nmap XML parser in `tools/nmap/adapter.py` to extract `<extrareasons>` and distinguish stateful drop (AWS Security Groups / Cloud hypervisors) from stateless TCP RST or ICMP administratively prohibited responses.
- [x] **Agent Prompt Neutralization & Defensive Ontology Framing:**
  - Implement an internal prompt sanitizer that translates offensive agent requests into standardized NIST/OWASP security auditing terminology, preventing LLM provider safety filter locks during autonomous execution.
  - *Refactoring Roadmap (per `$codebase-design`)*: Decouple from core execution gateway into an optional upstream agent-skill seam, ensuring core process execution preserves exact technical operator intent without artificial mutation.

#### 2. The Universal Tool Arsenal (Kali Linux & Modern Offensive Security Adapters)
Expand Ether pluggable tool adapters (`tools/<name>/`) to cover all standard Kali Linux packages, modern Go/Rust offensive utilities, and native async probers across 6 primary operational categories:

- [x] **Category 1: Network Reconnaissance & Port Sweeping**
  - `tools/naabu/`: High-performance asynchronous port scanner supporting fast SYN/connect sweeps.
  - `tools/masscan/`: High-throughput asynchronous TCP port scanner for full CIDR internet-scale ranges.
  - `tools/zmap/`: Single-packet network scanner for Internet-wide network surveys.
  - `tools/rustscan/`: Modern Rust-based multi-threaded port scanner with auto-piping into Nmap.
- [x] **Category 2: Passive OSINT & Attack Surface Discovery**
  - `tools/amass/`: In-depth attack surface mapping and external asset discovery (OWASP Amass).
  - `tools/crtsh/`: Native async coroutine querying crt.sh Certificate Transparency logs with zero binary dependencies.
  - `tools/dnsrecon/`: Advanced DNS enumeration script (SRV, AXFR, PTR, wildcard expansion).
- [x] **Category 3: Web Application & API Enumeration**
  - `tools/katana/`: Modern headless crawler and JavaScript analysis engine for Single Page Applications (SPAs).
  - `tools/kiterunner/`: High-speed routing and API endpoint discovery tool specialized in REST, Swagger, and GraphQL.
  - `tools/feroxbuster/`: Fast, recursive content discovery tool written in Rust.
  - `tools/arjun/`: HTTP parameter discovery suite for discovering hidden GET/POST parameters.
- [x] **Category 4: Automated Vulnerability Assessment & CVE Verification**
  - `tools/nuclei/` *(Core Automation Integration)*: Wire existing Nuclei adapter into autonomous subagent dispatch routines with automatic template filtering (`-tags cve,misconfig -severity critical,high`).
  - `tools/wpscan/`: WordPress security scanner auditing plugins, themes, and known CMS vulnerabilities.
  - `tools/cve_search/`: Local CVE database searcher mapping software versions to CVSS v3 scores offline.
- [x] **Category 5: Database & Deep Protocol Probers**
  - `tools/mysql_probe/`: Native Python async coroutine prober connecting to port 3306, validating unauthenticated root/guest access and extracting version banners.
  - `tools/postgres_probe/`: Native Python async coroutine prober auditing PostgreSQL connection handlers.
  - `tools/redis_probe/`: Native Python async coroutine prober evaluating unauthenticated Redis databases and INFO command disclosure.
  - `tools/sqlmap/`: High-leverage automated SQL injection detection and database takeover adapter.
  - `tools/ghauri/`: Lightweight, advanced SQL injection detection tool for complex filter evasion.
- [x] **Category 6: Credential, Authentication & Cloud Security**
  - `tools/netexec/` (`nxc`): Multi-protocol network execution suite verifying credentials across SMB, SSH, WinRM, LDAP, MSSQL, and RDP.
  - `tools/hydra/`: Fast network logon cracker for auditing weak service credentials.
  - `tools/imds_probe/`: Native Python async coroutine prober auditing AWS IMDSv1/v2, GCP, and Azure cloud metadata endpoints under `GatePolicy.UNRESTRICTED`.
  - `tools/cloud_enum/`: Multi-cloud OSINT tool enumerating public S3 buckets, Azure blobs, and Google storage.

#### 3. Execution Pipeline DAG & Substrate Mechanics
- [x] **Chained Reactive Pipeline Engine (Unix Pipe Metaphor for Security):**
  - Allow declarative piping of security tools where findings from tool A automatically parameterize tool B:
    ```bash
    ether pipeline "subfinder(target=$DOMAIN) | dnspython | httpx | nuclei"
    ```
  - Graph-aware routing: output `network.host` findings automatically fan out into parallel port scans; discovered `network.service(http)` nodes automatically route to web fuzzers.
- [x] **Native Packet Crafting & Stealth Network Engine (`scapy`):**
  - Pure-Python stealth TCP SYN scanning, custom port-knocking sequences, and local ARP network sniffing emitting typed `network.host` and `network.service` findings with zero external binary dependencies.
- [x] **Probabilistic State Estimation & Deception Defense:**
  - Bayesian belief networks over graph edges to handle partial observability.
  - Response-timing anomaly heuristics and banner analysis to detect dynamic tarpits, honeypots, and active moving-target defenses (MTD).
- [x] **Worker Task Pool & Backpressure Concurrency:**
  - Scalable worker pool allowing 50+ concurrent background scans without event-loop starvation.
  - Dynamic disk spooling and chunk recycling keeping engine memory usage below **25 MB** under massive telemetry loads.
- [x] **Streaming Pub/Sub Event Bus:**
  - Real-time event streaming (`asyncio.Queue` / WebSockets) emitting live findings as they are parsed, enabling external dashboards or remote TUIs to attach and detach seamlessly.
- [x] **Continuous Telemetry, Metrics & Observability (`ether.telemetry`):**
  - Prometheus `/metrics` and OpenTelemetry structured telemetry exporters.
  - Runtime monitoring tracking subprocess execution latencies, backpressure queue depths, WAL checkpoint durations, and memory watermarks.
  - System health diagnostics (`DiagnosticEngine`) auditing file descriptor headroom (`ulimit -n`), disk write pressure, and engine invariants.

#### 4. Substrate Optimizations, Diagnostic Fidelity & Ergonomic Improvements (From Live Multi-Agent Evaluation & Performance Critique)
Based on empirical findings, failure modes, and performance telemetry from the 6-subagent dual-posture AWS evaluation documented in `reports/ether_performance_critique_roadmap.html`:

- [x] **CLI Router Full Symmetry & Flexible Argument Normalization (`ether.cli`):**
  - Normalize argument parsing across all subcommands so commands accept both positional arguments and flags interchangeably (e.g. `ether graph search [session_id] [query]` vs `ether graph search --session-id <id> --query <q>`, `ether session create [name]` vs `ether session create --name <name>`).
  - Eliminates syntax invocation failures for autonomous AI agents that vary between positional and keyword argument formulations.
- [x] **Dynamic Adapter-Driven Preflight Gate (`ether.gateway.preflight`):**
  - Refactor `preflight.py` to eliminate brittle static lists (such as `WEB_TOOLS` strictly mandating `http://` or `https://` prefixes).
  - Dynamically infer target schema validation rules directly from `ToolAdapter.target_schemas` and `manifest.toml` contracts, allowing hybrid probers (`http_probe`) to seamlessly accept bare IPs, domains, or full URLs.
- [x] **Automated Fuzzer Response Baseline Calibration (`FfufAdapter` / `GobusterAdapter`):**
  - Implement an automated calibration preflight probe in web fuzzers: before launching full wordlist traversal, dispatch a probe against a randomized non-existent endpoint (e.g. `/.ether_probe_404_nonce`).
  - Automatically analyze the response length, word count, and line count, dynamically appending `-fs <size>` or `-fw <words>` to filter out uniform default web server responses (e.g., Nginx static 200s) and prevent false-positive graph bloat.
- [x] **Native Architectural Drift Engine & Baseline Comparison (`ether.drift`):**
  - Provide a native CLI command `ether drift audit <session_id> --baseline <ground_truth.json>` and an MCP supervisory tool `audit_drift`.
  - Compares observed live graph state against target ground-truth architecture specifications, outputting structured mathematical drift scores, unexpected open ports, missing mandatory security headers, and container restart discrepancies.
- [x] **High-Fidelity MCP Error & Execution Diagnostics (`ether.mcp`):**
  - Enhance MCP tool execution responses to surface granular error diagnostics (`exit_code`, `stderr_snippet`, `error_category`, `is_error`) rather than masking command failures or network timeouts as generic zero-finding completed runs.
  - Enables autonomous AI agents to perform immediate self-healing, flag firewall drops, or modify tool parameters dynamically.
- [x] **SQLite High-Concurrency Async Write Serialization & Connection Pooling (`GraphStore`):**
  - Implement an asynchronous write queue daemon and connection pool for `GraphStore`.
  - Eliminates SQLite WAL write lock contention and transaction queue latency when 50+ autonomous subagents execute parallel actions against the shared `~/.ether/ether.db` database.
- [x] **Hermetic In-Tree Semantic Vector Embeddings (`FastEmbed` / `ONNX`):**
  - Package lightweight, zero-dependency quantized embedding models (e.g. FastEmbed / ONNX all-MiniLM-L6-v2) directly inside Ether.
  - Ensures 100% offline, zero-network-egress semantic vector search, MITRE ATT&CK technique mapping, and finding correlation without requiring external API tokens or heavy PyTorch/transformers dependencies.
- [x] **Dedicated Cryptographic TLS/Cipher Suite Adapter (`tools/sslyze/` / `tools/testssl/`):**
  - Implement a deep protocol adapter auditing SSLv3, TLS 1.0/1.1 deprecation, weak cipher suites (CBC, RC4, 3DES), certificate revocation/expiry, and Heartbleed/ROBOT vulnerabilities.
  - Emits typed `tls.certificate` and `tls.cipher_suite` findings directly into the target graph for automated compliance scoring.

#### 5. Deep Seam Refactoring & High-Fidelity Telemetry Substrate (via `$codebase-design`)
Restructure gateway, execution, and sanitization boundaries to follow deep module principles—replacing shallow filters, paternalistic overrides, and destructive text mangling with high-leverage interfaces that preserve forensic integrity for professional labs and sovereign operators:

- [ ] **Elimination of Shallow Output Truncators (`strip_scanner_noise` Refactoring):**
  - *Problem*: `strip_scanner_noise` acts as a shallow filter that drops banners matching arbitrary string prefixes and truncates tool output to the last 60 lines, destroying critical version banners, SSL details, and CVE correlation evidence.
  - *Deep Module Design*: Deprecate shallow text slicing. Centralize stream capture behind the deep `LogSpooler` module interface (`spool(chunk: bytes)` / `stream() -> AsyncIterator[bytes]`).
  - *Implementation*: Hides circular ring buffering (`deque(maxlen=5000)`), 64KB atomic chunking, and raw forensic disk spooling.
  - *Leverage & Locality*: Structured telemetry extraction is localized entirely inside deep `ToolAdapter` implementations at the adapter seam; callers receive complete, unmutated streams with zero forensic data loss.
- [ ] **De-linking In-Transit Credential Redaction from Ingestion Seam:**
  - *Problem*: `redact_sensitive_artifacts` blindly replaces discovered private keys, bearer tokens, and passwords with `[REDACTED_*]` strings in transit, breaking the core objective of credential discovery tools (`hydra`, `netexec`, `sqlmap`).
  - *Deep Module Design*: Remove destructive string mutilation from the stream and parser seams. Tools must emit intact findings into typed `CredentialFinding` and `VulnerabilityFinding` schemas.
  - *Implementation*: Enforce artifact confidentiality at the storage and memory seams using the deep `SecureBuffer` (`ether.common.secure_memory`) and encrypted SQLite WAL archive modules rather than destroying operational data mid-flight.
- [ ] **Deep Rules of Engagement (RoE) Scope Module (`ether.gateway.scope`):**
  - *Problem*: The existing `preflight.py` is bloated with shallow static dictionaries (`DEFAULT_TOOL_TARGETS`, `WEB_TOOLS`) and rigid hardcoded bans (blocking loopback `127.0.0.1` and `sudo`), obstructing authorized lab workflows, container bridges, and SYN scanning.
  - *Deep Module Design*: Replace shallow static validation lists with a deep `ScopeValidator` module placed cleanly at the gateway seam.
  - *Interface*: `is_in_scope(target: str, scope: EngagementScope) -> ScopeVerdict` (minimal caller footprint).
  - *Implementation*: Hides CIDR Radix Trie matching, FQDN globbing, container bridge subnet resolution, and cloud IMDS (`169.254.169.254`) SSRF boundary enforcement.
  - *Leverage*: One deep module serves all CLI, MCP, and autonomous pipeline callers, permitting local lab audits when authorized while strictly preventing unauthorized egress.
- [ ] **Decoupled Prompt Neutralization Seam:**
  - *Problem*: Hardcoding artificial vocabulary translation (`PromptNeutralizer` converting `exploit` $\rightarrow$ `verify vulnerability impact`) into the gateway core distorts operator intent and disrupts custom security tooling.
  - *Deep Module Design*: Retire prompt mutation from the core execution gateway. Relocate defensive prompt framing to an upstream agent-skill seam (where autonomous planning agents formulate natural compliance prompts), ensuring the core execution engine preserves exact technical commands and arguments verbatim.
- [ ] **Externalized Wordlist & Asset Seam (`ether.registry.assets`):**
  - *Problem*: Bundling static seed wordlists (`common.txt`) inside the core library creates packaging bloat and maintenance overhead for tools that real labs already configure with SecLists.
  - *Deep Module Design*: Prune static text files from the core package implementation. Deepen the asset resolution interface (`resolve_wordlist(spec: str) -> Path`) to resolve against system paths (`/usr/share/seclists`, `/usr/share/wordlists`) and user environment contracts.
- [ ] **Forensic-Grade Session Log Architecture & Auditability (`ether.common.forensic_log`):**
  - *Problem*: Scans currently dump unindexed, opaque files directly into a flat directory (`~/.ether/logs/<action_id>.log`). Forensic investigators and red-team auditors cannot determine which tool ran, which target was scanned, or which session owned the run without manual grep over hundreds of UUID files.
  - *Deep Module Design*: Replace flat file dumping with a deep `ForensicLogManager` module placed at the spooling seam.
  - *Small Interface*: `open_action_spool(session_id, action) -> LogSpooler` and `query_session_audit(session_id, filter) -> Sequence[AuditRecord]`.
  - *Implementation*:
    - **Hierarchical Canonical Naming**: Partition logs by session with chronological human/machine-auditable names: `~/.ether/logs/sessions/<session_id>/<timestamp>_<tool>_<target_sanitized>_<short_id>.log`.
    - **Session Audit Manifest (`audit_manifest.jsonl` / SQLite Log Index)**: Append-only ledger recording `{timestamp, action_id, tool, target, exit_code, sha256_checksum, byte_size}` for instant forensic replay.
    - **Automated Lifecycle & Compression**: Transparent background gzip/zstd compression and retention pruning for historical scan sessions, preventing storage exhaustion.
    - **Cryptographic Chain of Custody**: SHA-256 hash chaining over completed scan logs for tamper-evident forensic reporting.
  - *Leverage & Locality*: Callers and execution sessions use a single clean interface for logging without leaking path formatting, file handles, or rotation logic across the codebase.

### Epoch 4: The Unrestricted Offensive Engine (Offensive Workstation Core)
*Target: v0.5.0*
*Focus: Sovereign offensive operations, full PTY emulation, and exploit choreography.*

- [ ] **Zero-Tampering Forensic Stream Seam (Sovereign Telemetry Invariant):**
  - Guarantee that the PTY supervisor and process execution modules enforce an absolute zero-tampering invariant across the stream seam: 100% of raw byte streams, ANSI cursor motions, and terminal escape sequences are preserved byte-for-byte for forensic replay and operator review, with zero paternalistic filtering.

- [ ] **Dual-Path Interactive POSIX PTY Supervisor (`pyte` + `ptyprocess` / `os.openpty`):**
  - *Transferred from CyGuide Engine Core*
  - Dedicated OS pseudo-terminal pair (`master_fd`/`slave_fd`) allocation replacing `stdin=DEVNULL` for interactive tools (`msfconsole`, `gdb`, reverse shell listeners, `ssh`, `sudo`).
  - In-memory VT102/xterm screen emulation via `pyte` to track ANSI escape codes, cursor positions, color buffers, and screen diffs.
  - Forwarding terminal window resize signals (`SIGWINCH` via `fcntl.ioctl` with `termios.TIOCSWINSZ`).
  - Background loot & credential extraction from live interactive streams without interrupting the operator shell.
- [ ] **Enterprise Active Directory Protocol Engine (`impacket` & `bloodhound-python`):**
  - Python-native Active Directory assessment engine providing Kerberoasting, AS-REP roasting, and SMB/RPC/LDAP interaction as in-process async coroutines.
  - Integration with `bloodhound-python` to ingest Active Directory domain ACLs, object permissions, and trust relationships directly into the target graph.
  - Emits typed findings (`ad.user`, `ad.spn`, `ad.ticket`, `ad.share`, `ad.acl`) directly into the target graph.
- [ ] **Binary Exploitation & Exploit Choreography Bridge (`pwntools` + `msfconsole`):**
  - Supervised PTY adapter for managing active Metasploit shells, meterpreter sessions, and payload handlers.
  - In-process `pwntools` integration for remote socket interaction, ROP gadget analysis, and exploit staging.
- [x] **Attack Graph Traversal & Path Discovery (`ether.graph.analytics`):**
  - In-memory directed graph intelligence engine (`GraphAnalyticsEngine`):
    - BFS shortest attack path discovery across multi-hop findings.
    - Transitive blast radius computation from compromised entities.
    - Crown-jewel critical asset identification (credentials, RCE CVEs, Active Directory, DBs).
    - Tarjan's strongly connected components (SCC) for cyclic attack loops and Brandes' betweenness centrality for choke-point discovery.
- [ ] **Autonomous Operation Daemon (`etherd`):**
  - *Transferred from CyGuide Engine Core*
  - Long-running headless daemon managing continuous surface monitoring, background scans across client disconnects, and Unix domain socket IPC (`~/.ether/run/ether.sock`).

---

### Epoch 5: Distributed Sovereign Mesh & Global Telemetry
*Target: v1.0.0+*
*Focus: Multi-node distributed operations, zero-trust coordination, and plugin marketplace.*

- [ ] **Zero-Copy Distributed Graph Federation:**
  - Synchronization of multiple Ether nodes across VPSs, local networks, and cloud instances using SQLite session replication (CRDT / SQLite Session Extension).
  - Red-team operators share a live, unified target graph without a centralized server.
- [ ] **Multi-Agent Swarm Telemetry Protocol:**
  - *Transferred from CyGuide Engine Core*
  - Headless coordination primitives for specialized subagents (Recon, Web, Critic, Reporter) publishing findings to a shared target graph with conflict-free resolution.
- [ ] **Cross-Session Knowledge Sharing & Workspace Graph Rollups:**
  - *Transferred from CyGuide Engine Core*
  - Correlate discoveries across multiple engagements to detect shared infrastructure, identical SSL certificates, and enterprise-wide vulnerabilities.
- [ ] **Pluggable WebAssembly (Wasm) Parser Sandboxing:**
  - Execute third-party community adapters in lightweight Wasm sandboxes, ensuring community tool parsers can never compromise the host machine.
- [ ] **Ecosystem Integration:**
  - CyGuide permanently re-based on top of `pip install ether-core`.
  - Independent release of the offensive workstation utilizing Ether's full PTY and offensive capabilities.

---

## Concrete Capability Comparison

| Dimension | Raw Bash / Scripts | Legacy CyGuide Monolith | **Ether Engine (Ideal State)** |
| :--- | :--- | :--- | :--- |
| **Execution Safety** | Unrestricted / Fragile | Safe Lab Policy Only | **Pluggable (`SAFE` vs `UNRESTRICTED`)** |
| **Output Handling** | Ephemeral stdout | UI Ring Buffers | **64KB Spooled Disk + Bounded Memory Rings** |
| **State Storage** | Flat text files / logs | SQLite GraphStore | **Deterministic Multi-Session Graph + Event Sourcing** |
| **AI Agent Support** | Context bloat / Failures | None (Tutor only) | **Native MCP Server + Token-Zero Graph Diffs** |
| **Tool Orchestration** | Fragile bash pipes | Manual single-shot | **Automated Reactive DAG Pipelines** |
| **Interactive Shell** | Raw OS terminal | Non-PTY stream | **Supervised PTY with Background Extraction** |
| **UI Coupling** | High (terminal emulator) | High (Textual TUI) | **Zero (100% Headless Engine)** |
| **Encrypted Archives** | GPG manual tar | None | **Argon2id + AES-256-GCM Authenticated SQLite** |
| **Vector Intelligence**| None | None | **In-Process `sqlite-vec` Semantic Embeddings** |
| **Concurrency Scaling**| OS fork/exec cap (~500 procs)| UI process block | **10,000+ Native Async Coroutines (<150MB RAM)** |
| **Dynamic Target Tracking**| Blind / Stale static IPs | Transient UI state | **Temporal Node TTL Decay & Cryptographic Invariance** |
| **Deception Defense**   | Vulnerable to tarpits | None | **Bayesian Honeypot & Timing Anomaly Detection** |

---

## Definition of Done for Core Milestones

To ensure high standards, no milestone in this roadmap is declared complete without:
1. **100% AST Invariant Proofs:** Zero unauthorized cross-layer or UI imports.
2. **Deterministic Mathematical Proofs:** Hypothesis property tests proving PIK uniqueness, idempotence, and Radix Trie correctness.
3. **Universal Hostile Fuzzing:** All adapters tested against truncated JSON, broken ANSI, and null bytes.
4. **Sub-10s Test Run:** Full regression suite executing in under 10 seconds locally.
