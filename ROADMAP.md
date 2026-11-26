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
 Decoupled        Autonomous       High-Throughput  Virtual PTY &    Distributed Mesh
 Foundation       Agent Gateway    Chained Mesh     Deep Inspection  & Autonomous Swarm
 (Substrate Core) (MCP & Diffs)    (DAG Pipelines)  (PTY, APK, Goals)(CRDTs, IDS, Fleet)
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

- [x] **Elimination of Shallow Output Truncators (`strip_scanner_noise` Refactoring):**
  - *Problem*: `strip_scanner_noise` acts as a shallow filter that drops banners matching arbitrary string prefixes and truncates tool output to the last 60 lines, destroying critical version banners, SSL details, and CVE correlation evidence.
  - *Deep Module Design*: Deprecate shallow text slicing. Centralize stream capture behind the deep `LogSpooler` module interface (`spool(chunk: bytes)` / `stream() -> AsyncIterator[bytes]`).
  - *Implementation*: Hides circular ring buffering (`deque(maxlen=5000)`), 64KB atomic chunking, and raw forensic disk spooling.
  - *Leverage & Locality*: Structured telemetry extraction is localized entirely inside deep `ToolAdapter` implementations at the adapter seam; callers receive complete, unmutated streams with zero forensic data loss.
- [x] **De-linking In-Transit Credential Redaction from Ingestion Seam:**
  - *Problem*: `redact_sensitive_artifacts` blindly replaces discovered private keys, bearer tokens, and passwords with `[REDACTED_*]` strings in transit, breaking the core objective of credential discovery tools (`hydra`, `netexec`, `sqlmap`).
  - *Deep Module Design*: Remove destructive string mutilation from the stream and parser seams. Tools must emit intact findings into typed `CredentialFinding` and `VulnerabilityFinding` schemas.
  - *Implementation*: Enforce artifact confidentiality at the storage and memory seams using the deep `SecureBuffer` (`ether.common.secure_memory`) and encrypted SQLite WAL archive modules rather than destroying operational data mid-flight.
- [x] **Deep Rules of Engagement (RoE) Scope Module (`ether.gateway.scope`):**
  - *Problem*: The existing `preflight.py` is bloated with shallow static dictionaries (`DEFAULT_TOOL_TARGETS`, `WEB_TOOLS`) and rigid hardcoded bans (blocking loopback `127.0.0.1` and `sudo`), obstructing authorized lab workflows, container bridges, and SYN scanning.
  - *Deep Module Design*: Replace shallow static validation lists with a deep `ScopeValidator` module placed cleanly at the gateway seam.
  - *Interface*: `is_in_scope(target: str, scope: EngagementScope) -> ScopeVerdict` (minimal caller footprint).
  - *Implementation*: Hides CIDR Radix Trie matching, FQDN globbing, container bridge subnet resolution, and cloud IMDS (`169.254.169.254`) SSRF boundary enforcement.
  - *Leverage*: One deep module serves all CLI, MCP, and autonomous pipeline callers, permitting local lab audits when authorized while strictly preventing unauthorized egress.
- [x] **Decoupled Prompt Neutralization Seam:**
  - *Problem*: Hardcoding artificial vocabulary translation (`PromptNeutralizer` converting `exploit` $\rightarrow$ `verify vulnerability impact`) into the gateway core distorts operator intent and disrupts custom security tooling.
  - *Deep Module Design*: Retire prompt mutation from the core execution gateway. Relocate defensive prompt framing to an upstream agent-skill seam (where autonomous planning agents formulate natural compliance prompts), ensuring the core execution engine preserves exact technical commands and arguments verbatim.
- [x] **Externalized Wordlist & Asset Seam (`ether.registry.assets`):**
  - *Problem*: Bundling static seed wordlists (`common.txt`) inside the core library creates packaging bloat and maintenance overhead for tools that real labs already configure with SecLists.
  - *Deep Module Design*: Prune static text files from the core package implementation. Deepen the asset resolution interface (`resolve_wordlist(spec: str) -> Path`) to resolve against system paths (`/usr/share/seclists`, `/usr/share/wordlists`) and user environment contracts.
- [x] **Forensic-Grade Session Log Architecture & Auditability (`ether.common.forensic_log`):**
  - *Problem*: Scans currently dump unindexed, opaque files directly into a flat directory (`~/.ether/logs/<action_id>.log`). Forensic investigators and red-team auditors cannot determine which tool ran, which target was scanned, or which session owned the run without manual grep over hundreds of UUID files.
  - *Deep Module Design*: Replace flat file dumping with a deep `ForensicLogManager` module placed at the spooling seam.
  - *Small Interface*: `open_action_spool(session_id, action) -> LogSpooler` and `query_session_audit(session_id, filter) -> Sequence[AuditRecord]`.
  - *Implementation*:
    - **Hierarchical Canonical Naming**: Partition logs by session with chronological human/machine-auditable names: `~/.ether/logs/sessions/<session_id>/<timestamp>_<tool>_<target_sanitized>_<short_id>.log`.
    - **Session Audit Manifest (`audit_manifest.jsonl` / SQLite Log Index)**: Append-only ledger recording `{timestamp, action_id, tool, target, exit_code, sha256_checksum, byte_size}` for instant forensic replay.
    - **Automated Lifecycle & Compression**: Transparent background gzip/zstd compression and retention pruning for historical scan sessions, preventing storage exhaustion.
    - **Cryptographic Chain of Custody**: SHA-256 hash chaining over completed scan logs for tamper-evident forensic reporting.
  - *Leverage & Locality*: Callers and execution sessions use a single clean interface for logging without leaking path formatting, file handles, or rotation logic across the codebase.

#### 6. Empirical Hardening & Operational Resilience (Resolving Run 1 Deficiencies)
Directly addressing the empirical bottlenecks, tool dropouts, and latency anomalies identified in the live multi-agent AWS benchmark (`reports/run_1/`):

- [x] **Hermetic Container Tool Execution & Automated Binary Provisioning (`ether.core.container`):**
  - *Problem from Run 1*: Autonomous agents failed to discover client-side Single-Page Application (SPA) routes on OWASP Juice Shop (`/#/login`, `/#/score-board`) and hidden API query parameters because `katana`, `arjun`, `sqlmap`, and `naabu` were missing from the host system environment.
  - *Deep Module Design*: Create a deep `ContainerizedToolRunner` placed at the execution supervisor seam.
  - *Seam Placement*: Execution supervisor seam (`ether.core.container.ContainerizedToolRunner`).
  - *Small Interface*: `execute_hermetic_tool(tool_name: str, target: str, args: Sequence[str], context: ExecutionContext) -> AsyncIterator[bytes]`.
  - *Implementation (Hidden Complexity)*:
    - Transparent binary presence check on system `$PATH`. If present locally, execute directly via pure argument vectors.
    - If absent, seamlessly fall back to an isolated, OCI-compliant container runtime (`podman` / `docker` / rootless `runc` using `ghcr.io/ether/arsenal:latest`) with mounts restricted to the specific target socket and log spool.
    - Zero host configuration: agents execute tool adapters uniformly without knowing whether a tool is a local binary, an in-process coroutine, or a containerized worker.
  - *Leverage & Locality*: Resolves the "missing tool" operational blind spot for any tool adapter across all host operating systems without polluting the host environment or requiring manual apt/brew installations.
  - *The Deletion Test*: Deleting this module would require human operators or deployment scripts to pre-install 37+ disparate binary dependencies manually on every agent machine.

- [x] **Ambient Raw Socket Acceleration & Stealth SYN Scanner (`ether.core.raw_net`):**
  - *Problem from Run 1*: Without root privileges, Nmap defaulted to unprivileged TCP Connect handshakes (`-sT`), ballooning scan latency to ~26.3 seconds per target host (5× slower than raw SYN scans).
  - *Deep Module Design*: Create a deep `RawNetworkGovernor` module placed at the network execution seam.
  - *Seam Placement*: Packet crafting and socket seam (`ether.core.raw_net.RawNetworkGovernor`).
  - *Small Interface*: `fast_syn_sweep(target: str, ports: Sequence[int], timeout_sec: float = 2.0) -> AsyncIterator[ServiceProbeResult]`.
  - *Implementation (Hidden Complexity)*:
    - Detects and acquires Linux ambient capabilities (`CAP_NET_RAW` / `CAP_NET_ADMIN`) or utilizes in-process Scapy/eBPF raw socket filters.
    - Emits asynchronous, non-blocking TCP SYN half-open probe bursts directly from the event loop, parsing incoming SYN-ACK / RST packets in under 1 second without child process fork overhead.
    - Automatically falls back to high-concurrency non-blocking connect coroutines (`asyncio.open_connection` pool) when raw socket access is strictly denied by OS hypervisors.
  - *Leverage & Locality*: All network reconnaissance adapters (`nmap`, `naabu`, `masscan`) query port state through a single optimized driver, reducing host discovery latency from 26 seconds to <1.5 seconds.
  - *The Deletion Test*: Deleting this module forces all network tools to either run as full root or suffer massive latency penalties from unprivileged OS TCP handshake handoffs.

- [x] **Resilient Heuristic Stream Chunk Recovery (`ether.core.recovery`):**
  - *Problem from Run 1*: When long-running external scanners (`nuclei`, `ffuf`) hit execution timeouts (e.g. Nuclei timing out at 35 seconds) or were terminated prematurely, trailing JSON streams were discarded, losing valuable in-flight findings discovered before process termination.
  - *Deep Module Design*: Deep `HeuristicStreamRecovery` module placed at the parser pipeline seam.
  - *Seam Placement*: Stream chunk normalization seam (`ether.core.recovery.StreamRecoveryEngine`).
  - *Small Interface*: `salvage_stream_chunks(damaged_buffer: bytes, expected_schema: Type[BaseFinding]) -> Sequence[BaseFinding]`.
  - *Implementation (Hidden Complexity)*:
    - Intercepts partial or malformed JSON/XML parser exceptions on process exit.
    - Employs streaming regex lookahead to identify complete, valid JSON objects within truncated array buffers (`[{...}, {...}, {"part...`), parsing valid entities while safely dropping only the corrupted terminal fragment.
    - Injects execution timeout markers directly into the session telemetry, distinguishing between target unresponsiveness, firewall tarpits, and local tool failure.
  - *Leverage & Locality*: Tool adapters retain 100% of partial findings even when commands time out or are cancelled, preventing lost intelligence during autonomous agent loops.
  - *The Deletion Test*: Deleting this module causes any interrupted or timed-out tool run to lose 100% of its findings, forcing redundant re-scans.

- [x] **Automated Storage Quota & Background Log Lifecycle (`ether.common.storage`):**
  - *Problem from Run 1*: High-throughput stress tests generated 26.5MB of uncompressed raw console logs in a single run. Continuous operations will exhaust host disk space over time.
  - *Deep Module Design*: Deep `StorageLifecycleManager` placed at the filesystem persistence seam.
  - *Seam Placement*: Spooling and storage persistence seam (`ether.common.storage.StorageLifecycleManager`).
  - *Small Interface*: `enforce_retention_policy(max_disk_mb: int = 1000, max_age_days: int = 30) -> StoragePruneReport`.
  - *Implementation (Hidden Complexity)*:
    - Background asynchronous worker monitoring the `~/.ether/logs/` tree.
    - Transparent on-disk Zstandard (`zstd`) compression for completed scan session logs (>90% compression ratio on terminal ANSI logs).
    - Hard disk watermark enforcement: automatically prunes oldest non-flagged forensic logs when directory size approaches configurable quota (default 1GB).
  - *Leverage & Locality*: Host machines maintain bounded disk usage indefinitely during 24/7 autonomous monitoring without requiring manual cron logrotate configurations.
  - *The Deletion Test*: Deleting this module leads to inevitable disk exhaustion during continuous fuzzing or large-scale network surveys.

- [x] **Adaptive Volatility Scoring & Rapid State Decay for High-Churn Cloud Targets (`GraphStore`):**
  - *Problem from Run 1*: The static 3600-second TTL decay was too coarse to capture containerized services mutating or restarting on 10-minute cycles (such as the vulnerable AWS container stack).
  - *Deep Module Design*: Implement adaptive volatility decay calculations directly inside `GraphStore`.
  - *Seam Placement*: Entity state machine seam (`ether.graph.store.GraphStore.apply_temporal_decay`).
  - *Implementation*:
    - Computes a mathematical volatility coefficient $V_n \in [0.1, 1.0]$ based on historical flapping frequency and container restart intervals.
    - Dynamically scales TTL window: highly stable bare-metal hosts maintain long confidence windows, while dynamic cloud containers accelerate confidence decay (`confirmed` $\rightarrow$ `flapping` $\rightarrow$ `stale`) in sub-15-minute cycles, matching real-world ephemeral cloud architectures.

#### 7. Autonomous Agent Usability, Security Boundary & Memory Hardening (Resolving Run 4 Deficiencies)
Directly addressing every deficiency, UX friction point, security edge case, and optimization identified during the Run 4 autonomous multi-agent evaluation (`reports/run_4/`):

- [x] **Full CLI `-j / --json` Symmetry & Un-truncated Graph IDs (`ether.cli`):**
  - *Problem from Run 4*: Passing `-j / --json` only produces JSON for `telemetry snapshot` and `telemetry diff`. Commands including `session create`, `session list`, `session verify-audit`, `graph list-nodes`, `graph belief`, `graph crown-jewels`, `graph blast-radius`, `graph attack-path`, `telemetry health`, `drift`, and `run` ignore `-j` and emit human-readable Rich text. Additionally, `graph list-nodes` truncates node IDs to 12 characters.
  - *Fix*: Honor `-j / --json` uniformly across all CLI subcommands and return full 64-character SHA-256 node IDs in JSON output so autonomous agents can chain `graph blast-radius` and `graph attack-path` without parsing ASCII tables.

- [x] **Byte-Bounded `ExecutionSession` Ring Buffers & Queue Backpressure (`src/ether/core/session.py`):**
  - *Problem from Run 4*: `_job_buffers` uses `deque(maxlen=5000)` which bounds chunk count rather than byte size. With `Executor` reading 64KB chunks, a 16.11 MB flood kept 258 chunks in `_job_buffers` and duplicated them in `_event_queues` for `subscribe()`, causing a **33.49 MB** peak RSS delta (18.32 MB post-GC) and failing the `<10 MB` memory cap.
  - *Fix*: Replace chunk-count-only `deque` with a byte-bounded ring buffer (`max_bytes <= 2 MB` per active job) and bounded `subscribe()` queues with drop-oldest backpressure so peak RSS delta remains strictly `<10 MB`.

- [x] **`GobusterAdapter` Linear-Time Regex Hardening (`tools/gobuster/adapter.py`):**
  - *Problem from Run 4*: `GobusterAdapter.STATUS_PATTERN = re.compile(r"(\S+)\s+\(Status:\s+(\d+)\)")` suffers from $O(N^2)$ catastrophic backtracking (ReDoS), hitting a 2.0s `SIGALRM` timeout on a 100,000-char whitespace-free line.
  - *Fix*: Pre-filter lines for `" (Status:"` and cap/slice line length or replace with linear-time `str.split` parsing so hostile streams parse in $O(N)$ time.

- [x] **Unified SSRF, DNS Resolution, Redirect & `--flags` Smuggling Defense (`ether.gateway` & `ether.common.scope`):**
  - *Problem from Run 4*:
    - `is_blocked_destination()` in `src/ether/gateway/gate.py` hardcodes `EngagementScope(allow_loopback=True)` when `allowed_cidrs` is unset, letting loopback/unspecified/302-redirector targets (`127.0.0.1`, `0.0.0.0`, `[::]`, `0177.0.0.1`, `2130706433`, `0`, `0x7f000001`) bypass `ActionGateway.validate_action()`.
    - `ActionGateway` and `PreflightVerifier` do not invoke `ScopeValidator.check_destination()` DNS resolution, allowing `nip.io` and `localtest.me` to bypass `SAFE` gates.
    - `PreflightVerifier._check_security()` never inspects `--flags` (12/12 smuggling bypasses); `ActionGateway` missed 6/12 flag-smuggling vectors (joined `-uhttp://...`, colon-delimited `--resolve=host:port:ip`, comma-delimited `--targets=a,b`, `--proxy`, `-L`).
    - `http_probe` lacks an HTTP redirect-following SSRF guard on `301`/`302`/`307`/`308` `Location` headers.
  - *Fix*: Default `allow_loopback=False` under `GatePolicy.SAFE` unless explicitly authorized, wire `check_destination()` DNS resolution into both `ActionGateway` and `PreflightVerifier`, tokenize and validate all `--flags` values (including joined/colon/comma forms), and validate redirect `Location` targets against `ScopeValidator` before following.

- [x] **XML Boundary Whitespace/Attribute Escaping (`src/ether/common/__init__.py`):**
  - *Problem from Run 4*: `sanitize_untrusted_output()` regex `r"</untrusted_scan_output>"` fails on 5/12 closing-tag variants containing whitespace or attributes (`</untrusted_scan_output >`, `</untrusted_scan_output\t>`, `</untrusted_scan_output\n>`, `</ untrusted_scan_output>`, `</untrusted_scan_output foo="bar">`) and leaves opening `<untrusted_scan_output>` tags unescaped.
  - *Fix*: Escape any `<(?:/\s*)?untrusted_scan_output\b[^>]*>` (case-insensitive) inside untrusted scanner outputs.

- [x] **Expanded Subprocess Environment Secret Scrubbing (`src/ether/core/executor.py`):**
  - *Problem from Run 4*: `sanitize_subprocess_env()` leaked 11/20 tested secrets to child subprocesses: `AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN`, `AWS_PROFILE`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `AZURE_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`, `DOCKER_PASSWORD`, `NPM_TOKEN`, `DATABASE_URL`, and `CUSTOM_API_KEY`.
  - *Fix*: Expand `sensitive_prefixes` and suffix patterns in `sanitize_subprocess_env()` to strip `AWS_`, `SSH_`, `AZURE_`, `GOOGLE_APPLICATION_CREDENTIALS`, `DOCKER_`, `NPM_`, `DATABASE_URL`, and `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_API_KEY`.

- [x] **Atomic Overwrite & `GraphStore` Directory Permissions (`src/ether/paths.py`, `src/ether/graph/store.py`):**
  - *Problem from Run 4*: `atomic_create_file()` leaves a pre-existing `0o644` file at `0o644` on overwrite, and `GraphStore` creates `db_dir` with `os.makedirs(db_dir, exist_ok=True)` without `mode=0o700` (yielding `0o755`) and relies on post-creation `os.chmod(self.db_path, 0o600)`.
  - *Fix*: Enforce atomic temp-file + `0o600` + `os.replace` in `atomic_create_file()`, create `db_dir` with `mode=0o700`, and pre-create `db_path` atomically with `0o600`.

- [x] **Deception Detection, Tarpit Timeout & Banner Correlation (`ether.graph.analytics`, `tools/nmap`, `tools/http_probe`):**
  - *Problem from Run 4*: `ether graph belief --evaluate` marked both the live Cowrie SSH honeypot (`SSH-2.0-Cowrie SSH Honeypot`) and the 66s SSH tarpit as `HONEYPOT: no`, `TARPIT: no`; `nmap` did not record the Cowrie banner in `network.service`; and `http_probe` stalled for 66s on the slow-drip tarpit despite `timeout=10.0s`.
  - *Fix*: Enforce strict total-request/read deadlines in `http_probe`, record raw service banners in `nmap` and a new lightweight native TCP/SSH banner-grabber coroutine adapter, and feed banner signatures + timing-anomaly telemetry into `GraphAnalyticsEngine.evaluate_deception()`.

- [x] **`http_probe` Body/Redirect Visibility & `imds_probe` Open-Redirect Detection (`tools/http_probe`, `tools/imds_probe`):**
  - *Problem from Run 4*: `http_probe` does not surface response body previews (e.g., `robots.txt` Disallow rules, `/api/internal/users` credential JSON) or 302 `Location` headers, and `imds_probe` returned 0 findings on `/redirect-imds`.
  - *Fix*: Surface sanitized response body snippets and redirect `Location` headers in `http_probe` findings, and teach `imds_probe` to flag open 302 redirects targeting cloud metadata endpoints.

- [x] **Target Input Classification & Graph Edge Wiring (`tools/tls_probe`, `ether.graph`):**
  - *Problem from Run 4*: `ether run tls_probe 127.0.0.1:34291` misclassified `IP:PORT` as `domain.info` and rejected it; `graph blast-radius` and `graph attack-path` returned 0 / no path due to missing/unconnected edges.
  - *Fix*: Parse `IP:PORT` inputs as `network.service` in `tls_probe` and `preflight.py`, and ensure `network.host` $\rightarrow$ `network.service` $\rightarrow$ `web.endpoint` $\rightarrow$ `vulnerability` edges are consistently wired.

- [x] **SDK Ergonomics, Out-of-Repo Auto-Init & MCP Metadata (`ether/__init__.py`, `ether/core/session.py`, `ether/mcp/server.py`):**
  - *Problem from Run 4*: `EngagementScope` is not exported from top-level `ether`; `ExecutionSession.__init__` requires explicit `gateway`, `registry`, and `command_runner`; standalone out-of-repo SDK `http_probe` failed with `OperationalError('no such table: sessions')`; and MCP `server_info.version` returned `""` instead of `"0.1.3"`.
  - *Fix*: Export `EngagementScope` at top level, provide sensible defaults on `ExecutionSession.__init__`, ensure `GraphStore` auto-initializes schema tables on first SDK use, populate MCP `server_info.version` dynamically from package metadata, and document `allow_loopback` / `policy` in MCP `execute_tool` schema.

#### 8. Architectural Assurance, Zero-Trust Hardening & Supply-Chain Integrity
Directly addressing the 14 architectural, cryptographic, and operational risks identified in rigorous external and container security reviews:

- [x] **Subprocess Argument Allowlisting & Flag Injection Firewall (`ether.gateway.flags`):**
  - *Problem*: Preflight validates target strings, but malicious or compromised MCP callers can inject dangerous flags via `flags` or `raw_flags` (e.g. `-oG`, `--script`, `--proxy`, `-oN`, `-iL`, `--config`, or shell metacharacters), bypassing the scope boundary.
  - *Deep Module Design*: Create a deep `FlagFirewall` module placed at the gateway preflight seam.
  - *Seam Placement*: Execution preflight seam (`ether.gateway.flags.FlagFirewall`).
  - *Minimal Interface Surface*:
    ```python
    class FlagFirewall:
        def validate_arguments(
            self, tool_name: str, args: Sequence[str], policy: GatePolicy
        ) -> Sequence[str]: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Derives strict argument AST schemas directly from `manifest.toml` contracts for all 35+ adapters.
    - Enforces strict allowlists for permitted flags; explicitly rejects proxy options, arbitrary script engines, and dangerous output redirect flags.
    - Disassembles and validates compound flags (joined `-uhttp://...`, colon-delimited `--resolve=host:port:ip`, comma-delimited `--targets=a,b`).
    - Strips shell interpolation characters (`|`, `;`, `&`, `$`, `` ` ``, `\n`) from all arguments prior to vector compilation.
  - *Leverage & Locality*: One centralized module protects every subprocess invocation across CLI, MCP, and autonomous pipelines without per-adapter manual regex checks.
  - *The Deletion Test*: Deleting this module allows callers to bypass scope enforcement by smuggling malicious targets inside arbitrary CLI flags.

- [x] **Enterprise MCP Gate & Scoped Transport Authentication (`ether.mcp.security`):**
  - *Problem*: Current MCP SSE authentication relies on a single Bearer token string equality check without brute-force rate-limiting, token rotation, mutual TLS (mTLS), scoped permissions (RBAC), request auditing, CORS origin policy, or segregation of read-only vs destructive operations.
  - *Deep Module Design*: Create a deep `SecurityMiddleware` placed at the transport ingress seam.
  - *Seam Placement*: Transport middleware seam (`ether.mcp.security.SecurityMiddleware`).
  - *Minimal Interface Surface*:
    ```python
    class SecurityMiddleware:
        async def authenticate_request(
            self,
            headers: Mapping[str, str],
            client_cert: Optional[bytes],
            operation: OperationType,
        ) -> AuthContext: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Constant-time HMAC comparison preventing timing attacks.
    - Sliding-window token rotation with grace periods and IP leaky-bucket brute-force defense.
    - Optional mutual TLS (mTLS) client certificate verification for zero-trust enterprise deployments.
    - Fine-grained permission scopes (`telemetry:read`, `graph:query`, `tool:execute`, `session:mutate`) with strict segregation of read-only vs destructive tool verbs.
    - Strict CORS origin whitelisting and structured request audit logging.
  - *Leverage & Locality*: Protects stdio, SSE, and HTTP transports identically behind a single authentication context.
  - *The Deletion Test*: Deleting this module scatters transport authentication, rate-limiting, and authorization checks across every individual MCP tool handler.

- [x] **Cryptographic Plugin Attestation & Sandboxed Loader (`ether.registry.loader`):**
  - *Problem*: `ToolRegistry` dynamically imports and executes arbitrary Python adapter modules from disk without digital signatures or integrity attestation, creating arbitrary code execution risks.
  - *Deep Module Design*: Create a deep `PluginLoader` module placed at the registry seam.
  - *Seam Placement*: Adapter registry seam (`ether.registry.loader.PluginLoader`).
  - *Minimal Interface Surface*:
    ```python
    class PluginLoader:
        def load_verified_adapter(self, adapter_path: Path, manifest_path: Path) -> ToolAdapter: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Ed25519 signature verification against embedded or trusted public keys.
    - SHA-256 cryptographic hash verification against official manifest registries.
    - AST static analysis checking for unauthorized `eval`, `exec`, or socket instantiation inside parser code.
    - Execution within isolated namespaces or WebAssembly sandboxes.
  - *Leverage & Locality*: Third-party and enterprise community adapters can be safely installed and loaded without risking host compromise.
  - *The Deletion Test*: Deleting this module allows untrusted or tampered adapter scripts to execute arbitrary code within the supervisor process.

- [x] **Transparent Database Cryptography & Credential Protection (`ether.graph.crypto`):**
  - *Problem*: Lossless credential findings are stored in plaintext SQLite databases at rest, protected only by filesystem permissions without transparent encryption, OS keyring integration, or per-field ACLs.
  - *Deep Module Design*: Create a deep `CryptoEngine` module placed at the storage persistence seam.
  - *Seam Placement*: Storage persistence seam (`ether.graph.crypto.CryptoEngine`).
  - *Minimal Interface Surface*:
    ```python
    class CryptoEngine:
        def open_encrypted_store(self, db_path: Path, passphrase_or_key: bytes) -> GraphStore: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Transparent database page encryption via SQLCipher / ChaCha20-Poly1305.
    - Automatic integration with OS keyrings (`secretstorage`, macOS Keychain, Linux Keyring) for master key retrieval.
    - Field-level cryptographic masking and access controls for credentials (`CredentialFinding`).
    - Credential TTL expiration and in-memory zero-leakage clearing via `ctypes.memset`.
  - *Leverage & Locality*: All finding queries and mutations operate transparently while data at rest is mathematically protected against physical or disk-level compromise.
  - *The Deletion Test*: Deleting this module leaves discovered passwords, API keys, and private keys exposed in plaintext SQLite files.

- [x] **Exact-Ownership WriteQueue Serialization & Mutation Integrity (`ether.graph.write_queue`):**
  - *Problem*: `WriteQueue` batch coalescing slices results by input offset (`all_nids[s:e]`), which breaks caller attribution when findings are deduplicated or share nodes. Furthermore, `export_session` and `import_session` perform direct SQL operations bypassing the write queue.
  - *Deep Module Design*: Deepen `WriteQueue` to eliminate offset slicing and serialize all mutations.
  - *Seam Placement*: SQLite write serialization seam (`ether.graph.write_queue.WriteQueue`).
  - *Minimal Interface Surface*:
    ```python
    class WriteQueue:
        async def enqueue_upsert(
            self, session_id: str, findings: Sequence[BaseFinding]
        ) -> UpsertResult: ...
        async def enqueue_mutation(
            self, operation_callable: Callable[[aiosqlite.Connection], Any]
        ) -> Any: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Eliminates offset slicing; maintains an internal reverse PIK lookup mapping (`Dict[PIK, NodeId]`) returning exact, uncorrupted finding results per caller.
    - Routes all database mutations—including session export, import, and schema migrations—through the serialized write worker.
  - *Leverage & Locality*: Guarantees zero database deadlocks, zero lock timeouts, and 100% correct result attribution across 50+ concurrent agents.
  - *The Deletion Test*: Deleting this module re-introduces SQLite write lock contention and corrupts finding attribution in multi-agent workflows.

- [x] **Two-Phase Atomic Session Sealer & Signed Audit Trail (`ether.common.session_sealer`):**
  - *Problem*: Session closure runs log compression before the SQLite status update; a crash leaves inconsistent states. The SHA-256 hash chain is append-only by convention and can be altered by a local attacker with filesystem write access.
  - *Deep Module Design*: Create a deep `SessionSealer` module placed at the session lifecycle seam.
  - *Seam Placement*: Session lifecycle seam (`ether.common.session_sealer.SessionSealer`).
  - *Minimal Interface Surface*:
    ```python
    class SessionSealer:
        async def seal_session(
            self, session_id: str, private_key: Optional[bytes] = None
        ) -> SealReceipt: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Two-phase commit state machine (`ACTIVE` $\rightarrow$ `SEALING` $\rightarrow$ `COMPRESSING` $\rightarrow$ `SEALED`) backed by a persistent recovery journal.
    - Cryptographic asymmetric signing (Ed25519) over the completed audit manifest and SHA-256 log hash chain, anchoring forensic integrity to an external key or system trust anchor.
  - *Leverage & Locality*: Forensic session closure is guaranteed atomic and cryptographically tamper-evident even across power loss or process crashes.
  - *The Deletion Test*: Deleting this module allows partial compression crashes to corrupt session archives and leaves audit trails vulnerable to local tampering.

- [x] **DNS-Pinned Socket Transport & Rebinding Defense (`ether.common.transport`):**
  - *Problem*: Pre-connect target validation does not pin IP addresses to TCP sockets; a malicious server can return an approved public IP on initial DNS resolution and redirect to an internal IP (e.g. `169.254.169.254` or `127.0.0.1`) via DNS rebinding.
  - *Deep Module Design*: Create a deep `PinnedTransport` module placed at the HTTP transport seam.
  - *Seam Placement*: HTTP network client seam (`ether.common.transport.PinnedTransport`).
  - *Minimal Interface Surface*:
    ```python
    class PinnedTransport:
        def create_client(self, scope: EngagementScope) -> httpx.AsyncClient: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Custom socket factory that resolves DNS once, validates the resolved IP against CIDR scope, and explicitly pins the TCP handshake directly to the validated IP.
    - Intercepts HTTP redirect responses (`301`/`302`/`307`), re-validates the new target, and enforces socket pinning on every redirect hop.
  - *Leverage & Locality*: Completely eliminates DNS rebinding and redirect SSRF across all web and API tools.
  - *The Deletion Test*: Deleting this module leaves every HTTP probe and web adapter vulnerable to Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.

- [x] **Least-Privilege Scanner Isolation & Capability Sandboxing (`ether.core.privilege`):**
  - *Problem*: Granting `cap_net_raw,cap_net_admin` to `/usr/bin/nmap` via `setcap` inside containers creates a capability escalation target if the Python supervisor is compromised.
  - *Deep Module Design*: Create a deep `PrivilegeGovernor` module placed at the execution isolation seam.
  - *Seam Placement*: Execution isolation seam (`ether.core.privilege.PrivilegeGovernor`).
  - *Implementation*:
    - Drops all Linux capabilities from the main Python supervisor process.
    - Segregates raw packet scanning into an isolated rootless network namespace or dedicated worker container communicating strictly over Unix domain sockets with read-only state mounts.
  - *Leverage & Locality*: Eliminates capability escape vectors while preserving high-speed raw packet scanning.
  - *The Deletion Test*: A compromised Python dependency can access ambient raw network capabilities on the host.

- [x] **Supply-Chain Security, Provenance Attestation & Reproducible Benchmarks:**
  - Enforce cryptographic dependency lockfile verification (`uv.lock` with hashes).
  - Generate automated Software Bill of Materials (SBOM in CycloneDX / SPDX format) and Sigstore/Cosign container image signatures.
  - Provide a reproducible benchmark harness capturing exact commit, hardware, kernel, Python version, workload, variance, and CI test artifacts.
  - Adversarial boundary test suite: file permission races, DNS rebinding, redirect chains, container breakout assumptions, SSE concurrency timeouts, and audit tampering.

### Epoch 4: The Unrestricted Virtual PTY & Enterprise Identity Engine
*Target: v0.5.0*
*Focus: POSIX pseudo-terminal virtualization, in-memory VT102 screen emulation, Active Directory & Cloud IAM graph calculus, and autonomous background daemonization.*

- [ ] **Dual-Path Interactive POSIX PTY Supervisor (`ether.core.pty`):**
  - *Problem*: Current process supervision routes standard I/O via non-interactive pipes with `stdin=DEVNULL`. Interactive security utilities (`msfconsole`, `gdb`, reverse shell listeners, interactive SSH, password challenges, and `sudo`) hang, fail to allocate terminal buffers, or corrupt ANSI cursor state.
  - *Deep Module Design*: Replace shallow pipe wrappers with a deep `PtySupervisor` module placed at the execution seam.
  - *Seam Placement*: Process execution seam (`ether.core.pty.PtySupervisor`).
  - *Minimal Interface Surface*:
    ```python
    class PtySession:
        async def write(self, data: bytes) -> None: ...
        async def read_screen(self) -> ScreenMatrix: ...
        async def resize(self, rows: int, cols: int) -> None: ...
        async def terminate(self, grace_period_sec: float = 5.0) -> int: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Dedicated OS pseudo-terminal allocation (`master_fd`/`slave_fd` via `os.openpty`).
    - In-memory headless VT102/xterm screen state machine via `pyte` tracking 2D character matrices, ANSI color buffers, cursor coordinates, and scrollback ring buffers.
    - Asynchronous non-blocking I/O loop (`asyncio.get_running_loop().add_reader`) streaming bytes directly to 64KB disk spools without event loop starvation.
    - Transparent propagation of window resize signals (`SIGWINCH` via `fcntl.ioctl` with `termios.TIOCSWINSZ`).
    - Passive in-stream telemetry hook: evaluates raw byte streams with non-destructive regex scanners to extract credentials and session tokens in real time without modifying or delaying byte delivery.
  - *Leverage & Locality*: Callers (CLI operators, MCP agents, automated scripts) receive an identical, clean `PtySession` handle; raw terminal control sequences, terminal emulator state machines, and OS signal wiring are encapsulated in one module.
  - *The Deletion Test*: Deleting this module would force every calling agent or CLI command to manually juggle raw terminal termios flags, manage OS file descriptors, and parse ANSI escape sequences.

- [ ] **Zero-Tampering Sovereign Telemetry Seam (Forensic Integrity Invariant):**
  - Enforce an absolute zero-tampering invariant across the PTY and subprocess stream seams: 100% of raw byte streams, ANSI cursor motions, and terminal escape sequences are preserved byte-for-byte for forensic replay and operator review, with zero paternalistic filtering.
  - Provide an append-only terminal session replay stream (`.cast` / asciinema format) directly from the underlying disk spool.

- [ ] **Enterprise Active Directory & Cloud Identity Graph Engine (`ether.graph.identity`):**
  - *Problem*: Discovered network hosts and open ports are disconnected from enterprise authorization structures. Attack paths traversing LDAP permissions, Kerberos tickets, and Cloud IAM trust relationships cannot be evaluated in a flat network graph.
  - *Deep Module Design*: Replace ad-hoc script parsing with a deep `EnterpriseIdentityEngine` placed at the graph modeling seam.
  - *Seam Placement*: Graph domain layer (`ether.graph.identity.IdentityEngine`).
  - *Minimal Interface Surface*:
    ```python
    class IdentityEngine:
        async def ingest_identity_finding(self, finding: BaseFinding) -> NodeId: ...
        async def compute_privilege_path(
            self, session_id: str, source_node: NodeId, target_node: NodeId
        ) -> AttackPath: ...
        async def calculate_blast_radius(
            self, session_id: str, compromised_node: NodeId
        ) -> BlastRadius: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Pure-Python in-process asynchronous protocol adapters querying LDAP, Kerberos, and SMB using `impacket` and native coroutines (Kerberoasting, AS-REP roasting, domain controller trust enumeration).
    - BloodHound graph ontology normalization: ingests `MemberOf`, `GenericAll`, `WriteDacl`, `AllExtendedRights`, and `AddMember` edges directly into SQLite `graph_edges`.
    - Unified Cloud IAM graph expansion: ingests AWS IAM policies, Azure Entra ID service principals, and GCP service account keys, modeling cross-cloud assume-role trust chains.
    - Graph path calculus: directed multi-hop shortest attack path evaluation, transitive blast radius reachability, and automated choke-point identification (Brandes' betweenness centrality).
  - *Leverage & Locality*: One deep module handles Active Directory, cloud permissions, and path traversal without exposing LDAP queries, ASN.1 parsing, or graph traversal mathematics to external callers.
  - *The Deletion Test*: Deleting this module would scatter Kerberos ticket parsing, BloodHound JSON transformation, and graph pathfinding algorithms across disparate tool adapters.

- [ ] **Cross-Platform Binary & Mobile Package Inspection (`ether.analysis.artifact`):**
  - *Problem*: Security engineers and autonomous agents need to audit compiled binaries, mobile applications, and system artifacts across diverse platforms (Android APK, macOS Mach-O, iOS IPA, Windows PE, Linux ELF). Current workflows rely on fragmented, ad-hoc CLI tools (`jadx`, `apktool`, `rabin2`, `checksec`, `codesign`, `otool`) emitting incompatible text formats and requiring complex host orchestration.
  - *Deep Module Design*: Create a unified `ArtifactAnalyzer` module placed at the artifact inspection seam.
  - *Seam Placement*: Binary and package analysis seam (`ether.analysis.artifact.ArtifactAnalyzer`).
  - *Minimal Interface Surface*:
    ```python
    class ArtifactAnalyzer:
        async def inspect_artifact(
            self, artifact_path: Path, config: AnalysisConfig | None = None
        ) -> ArtifactFinding: ...
        async def extract_decompilation(
            self, artifact_path: Path, symbol_or_class: str
        ) -> DecompilationResult: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Magic-byte container identification: automatically disambiguates ELF, PE/COFF, Mach-O (thin and universal fat binaries), Android DEX/APK ZIP bundles, and iOS IPA archives.
    - Platform-specific deep static inspection:
      - **Android APK**: Manifest parsing (`AndroidManifest.xml`), dangerous permissions, exported components (Activities, Services, Broadcast Receivers), debuggable flags, intent-filter vulnerabilities, and native `.so` library checks.
      - **macOS / iOS (Mach-O / IPA)**: Entitlements plist extraction, codesigning certificate validation, Provisioning Profile verification, Hardened Runtime checks, dynamic library load commands (`LC_LOAD_DYLIB`), and dylib hijacking risks.
      - **Linux ELF / Windows PE**: Binary mitigation auditing (RELRO, stack canaries, NX/DEP, PIE/ASLR, SafeSEH, Authenticode digital signatures), import/export address tables (IAT/EAT), and Shannon entropy calculation across sections (packer/crypter detection).
      - **Reverse Engineering**: Headless disassembly and decompilation via in-process binary parsers and headless decompiler bindings (rizin/radare2, Ghidra headless, JADX decompiler coroutines).
    - Maps all discovered artifacts into deterministic graph nodes (`binary.executable`, `binary.mitigation`, `mobile.permission`, `mobile.component`) indexed by SHA-256 Primary Identity Keys.
  - *Leverage & Locality*: One uniform method call (`inspect_artifact`) handles any binary or mobile package regardless of target operating system; format identification, archive decompression, bytecode parsing, and symbol demangling are completely encapsulated.
  - *The Deletion Test*: Deleting this module would force calling agents or scripts to maintain 8 separate tool pipelines, manually unzip APKs/IPAs, parse XML/plist files, and calculate binary entropy by hand.

- [ ] **Binary Exploitation & Exploit Choreography Bridge (`ether.core.interactive`):**
  - Supervised PTY adapter for managing active Metasploit shells, meterpreter sessions, and payload handlers.
  - In-process `pwntools` integration for remote socket interaction, ROP gadget analysis, and exploit staging.
  - Programmatic session handover: seamless transition from autonomous scanning to interactive operator exploitation shells.

- [x] **Attack Graph Traversal & Path Discovery (`ether.graph.analytics`):**
  - In-memory directed graph intelligence engine (`GraphAnalyticsEngine`):
    - BFS shortest attack path discovery across multi-hop findings.
    - Transitive blast radius computation from compromised entities.
    - Crown-jewel critical asset identification (credentials, RCE CVEs, Active Directory, DBs).
    - Tarjan's strongly connected components (SCC) for cyclic attack loops and Brandes' betweenness centrality for choke-point discovery.

- [ ] **Autonomous Operation Daemon & Continuous Goal Schedulers (`etherd` & `ether.workflow.engine`):**
  - *Problem*: Complex security operations (continuous attack surface monitoring, periodic credential rotation audits, automated patch verification, and multi-day threat hunting loops) require durable scheduling, timer jitter, and event-triggered workflow execution. Currently, invocations are primarily single-shot or linear CLI pipelines.
  - *Deep Module Design*: Create a deep `WorkflowEngine` integrated into the headless `etherd` daemon placed at the orchestration seam.
  - *Seam Placement*: Execution orchestration seam (`ether.workflow.engine.WorkflowEngine`).
  - *Minimal Interface Surface*:
    ```python
    class WorkflowEngine:
        async def register_goal(self, spec: GoalSpecification, trigger: TriggerPolicy) -> GoalId: ...
        async def get_goal_status(self, goal_id: GoalId) -> GoalProgress: ...
        async def cancel_goal(self, goal_id: GoalId) -> None: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Flexible trigger semantics: Cron schedules (`"0 */4 * * *"`), interval timers with anti-correlation jitter, and reactive graph-delta triggers (e.g. automatically trigger Katana web crawling whenever a new `network.service(http)` node is upserted into the graph).
    - Reactive State Machine & Convergence Tracking: Models multi-step workflows as directed state graphs where steps evaluate graph deltas ($\Delta = S_{t+1} \setminus S_t$) to verify goal convergence (e.g. "all newly discovered services have been audited and verified").
    - Persistent SQLite-backed task queue: durable task scheduling that survives process restarts or machine reboots without losing workflow state or progress.
    - Dynamic backpressure and resource budgets: caps concurrency, network bandwidth, and memory consumption during continuous background monitoring.
    - Headless daemon management: long-running service over Unix domain sockets (`~/.ether/run/ether.sock`) with automatic resource reclamation and client reconnection multiplexing.
  - *Leverage & Locality*: Callers define high-level security goals and triggers in clean YAML/JSON specifications; durable scheduling, event listening, retry policies, and convergence checking are 100% managed inside the engine.
  - *The Deletion Test*: Deleting this module would require external orchestration (cron, systemd timers, Celery, or external workflow engines) and custom graph polling scripts to be written for every continuous monitoring task.

---

### Epoch 5: Distributed Sovereign Mesh & Sandboxed Ecosystem
*Target: v1.0.0+*
*Focus: Peer-to-peer state federation, continuous host/network intrusion sensing, conflict-free multi-agent graph synchronization, and WebAssembly parser sandboxing.*

- [ ] **Distributed Graph Federation & CRDT State Synchronization (`ether.graph.federation`):**
  - *Problem*: Multiple operators or autonomous agents executing scans across distinct network segments (cloud VPS, local network, client container) maintain fragmented local databases (`~/.ether/ether.db`), causing blind spots and redundant scanning.
  - *Deep Module Design*: Create a deep `GraphFederationEngine` placed at the storage persistence seam.
  - *Seam Placement*: SQLite synchronization seam (`ether.graph.federation.FederationEngine`).
  - *Minimal Interface Surface*:
    ```python
    class FederationEngine:
        async def join_mesh(self, peer_address: str, auth_token: bytes) -> MeshNode: ...
        async def export_delta(self, since_vector_clock: VectorClock) -> bytes: ...
        async def apply_peer_delta(self, payload: bytes) -> SyncSummary: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Delta-state and state-based Conflict-free Replicated Data Types (CRDTs) layered on top of the SQLite session extension and append-only event logs.
    - Deterministic conflict resolution for finding attributes using Last-Write-Wins (LWW) registers backed by Lamport timestamps, and monotonic Grow-Only Sets (G-Set) for graph relationships (`graph_edges`).
    - Cryptographic mutual authentication and end-to-end payload encryption using authenticated Diffie-Hellman (X25519 + ChaCha20-Poly1305).
    - Peer-to-peer gossip protocol over lightweight asynchronous transport (WebSockets / TLS sockets) with automatic network partition recovery.
  - *Leverage & Locality*: Callers query and mutate their local `GraphStore` identically whether running on an isolated laptop or as part of a 20-node distributed fleet; network transport, serialization, vector clocks, and conflict resolution are 100% hidden.
  - *The Deletion Test*: Deleting this module would require every agent or operator script to implement manual database export/import reconciliation, resolving primary key collisions by hand.

- [ ] **Continuous Host & Network Intrusion Sensing Engine (`ether.telemetry.sensor`):**
  - *Problem*: Threat detection and blue-team telemetry requires correlating real-time host events (process spawning, socket binds, file modifications) and network flows (DNS queries, TLS handshakes, anomalous packet bursts). Ad-hoc log parsing is disconnected from Ether's deterministic graph.
  - *Deep Module Design*: Deep `IntrusionSensorEngine` placed at the telemetry ingestion seam.
  - *Seam Placement*: Telemetry ingestion and intrusion detection seam (`ether.telemetry.sensor.IntrusionSensorEngine`).
  - *Minimal Interface Surface*:
    ```python
    class IntrusionSensorEngine:
        async def attach_sensor(self, profile: SensorProfile) -> SensorHandle: ...
        async def stream_detections(self, session_id: str) -> AsyncIterator[IntrusionFinding]: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Multi-source telemetry ingestion: eBPF tracepoints (Linux `execve`, `connect`, `security_file_open`), macOS Endpoint Security Framework / `auditd` stream, Windows Event Log / Sysmon bridge.
    - Passive network packet dissection: Scapy/pcap coroutines extracting live DNS queries, TLS Server Name Indication (SNI), and ARP anomalies with zero external daemon requirements.
    - In-memory behavioral state machine: maintains sliding-window process lineage trees (parent-child PID graphs), correlating anomalous CLI arguments or reverse shells with MITRE ATT&CK techniques (T1059, T1071).
    - Sigma rule evaluation: in-process YAML Sigma rule compiler evaluating incoming event streams against behavioral attack signatures with sub-millisecond latency.
  - *Leverage & Locality*: Callers subscribe to structured `IntrusionFinding` events without needing to know whether the signal originated from eBPF, a passive pcap tap, or auditd; all signals are normalized into the unified entity graph.
  - *The Deletion Test*: Deleting this module would require callers to write custom eBPF filters, parse pcap files, and maintain process tree state across raw syscall streams.

- [ ] **Autonomous Multi-Agent Swarm Telemetry Protocol (`ether.telemetry.swarm`):**
  - Headless coordination primitives for specialized subagents (Recon, Web Fuzzing, Cloud IAM, Vulnerability Validator, Reporter) collaborating over a unified graph.
  - Event-driven graph change notification bus (`asyncio.Queue` / distributed pub-sub) allowing subagents to subscribe to specific graph delta types (e.g. agent B automatically triggers when agent A discovers a new `network.service(http)` node).
  - Conflict-free collaborative task dispatch ensuring parallel subagents do not execute redundant scans on identical targets.

- [ ] **Pluggable WebAssembly (Wasm) Parser Sandboxing (`ether.registry.wasm`):**
  - *Problem*: Community tool adapters written in Python execute inside the main engine address space with full process privileges. Malicious or malformed third-party adapters can access host files, corrupt internal state, or execute arbitrary code.
  - *Deep Module Design*: Replace unconstrained Python adapter execution with a deep `WasmParserRuntime` module placed at the adapter registry seam.
  - *Seam Placement*: Adapter execution and parsing seam (`ether.registry.wasm.WasmAdapterRunner`).
  - *Minimal Interface Surface*:
    ```python
    class WasmAdapterRunner:
        def load_adapter(self, wasm_binary: bytes, manifest: AdapterManifest) -> ToolAdapter: ...
        def parse(self, raw_stream: bytes) -> Sequence[BaseFinding]: ...
    ```
  - *Implementation (Hidden Complexity)*:
    - Sandboxed WebAssembly runtime engine (via `wasmtime` / `wasmer`) enforcing strict memory virtualization.
    - Hard resource bounds: strict memory quota (<16MB linear memory per instance) and CPU instruction count limits (fuel consumption) preventing parser ReDoS or infinite loops.
    - Zero host access invariant: zero filesystem access, zero environment variable exposure, and zero network socket capabilities inside the Wasm guest.
    - High-throughput linear memory ABI passing raw chunk buffers in and streaming validated JSON finding schemas out.
  - *Leverage & Locality*: Third-party contributors and community repositories can distribute pre-compiled tool parsers without security vetting of host code; the engine runs community adapters with mathematical safety guarantees.
  - *The Deletion Test*: Deleting this module forces users to either restrict themselves to built-in adapters or risk host compromise running arbitrary third-party parser scripts.

- [ ] **Cross-Session Knowledge Sharing & Workspace Graph Rollups:**
  - Correlate discoveries across multiple chronological engagements to detect persistent shared infrastructure, recurring SSL certificates, and enterprise-wide architectural trends.
  - Historical diffing engine tracking perimeter evolution and remediation verification over time.

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
