# Ether Master Engineering Roadmap: The Ideal State

This authoritative roadmap outlines the evolution of **Ether** from its current foundation as a decoupled process supervisor to its **highest imagined ideal state: The Autonomous Telemetry Substrate for Cybersecurity Operations**.

---

## The Vision: The "Cybersecurity Kernel"

Every modern computing environment has an operating system kernel that multiplexes hardware, manages processes, provides IPC, and maintains filesystem state without caring which applications run on top.

**Ether is that kernel for cybersecurity operations.**

Instead of human operators and AI agents clumsily spawning raw bash subshells and drowning in thousands of unstructured stdout lines, Ether provides:
1. **Universal Execution Virtualization:** Sandboxed process supervision, secret scrubbing, and backpressure-regulated streaming.
2. **Deterministic World State:** A reactive graph database where hosts, ports, web applications, credentials, and CVEs are deduplicated and merged on-the-fly via mathematical Primary Identity Keys (PIK).
3. **Pluggable Policy Isolation:** Running seamlessly in **Safe Mode** (for labs/universities like CyGuide) or **Unrestricted Beast Mode** (for sovereign red-teams and autonomous offensive loops).
4. **Agent Telemetry Protocol:** Zero-token diff streaming via the Model Context Protocol (MCP), turning raw scanner noise into structured episodic memory for AI reasoning models.
5. **Decoupled Architecture:** 100% headless core. Zero presentation or terminal emulator code. Consumed upstream by CyGuide (pedagogical TUI), headless DAEMONS (`etherd`), and autonomous AI swarms.

---

## The Five Evolutionary Epochs

```text
 Epoch 1 ───────► Epoch 2 ───────► Epoch 3 ───────► Epoch 4 ───────► Epoch 5
 Decoupled        Autonomous       High-Throughput  Unrestricted     Distributed
 Foundation       Agent Gateway    Chained Mesh     Beast Engine     Sovereign Fleet
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
- [x] **Comprehensive Regression Suite:** 217 unit and integration tests passing in <12s.
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
- [ ] **Encrypted Session Database Archives (`cryptography`):**
  - *Transferred from CyGuide Engine Core*
  - AES-256-GCM authenticated encryption for exported session databases with Argon2id passphrase key derivation (`ether graph export --encrypt`).
  - Cryptographic verification test suite rejecting truncated, bit-flipped, or tampered archives.
- [ ] **Zero-Leakage In-Memory Credential & Secret Scrubbing:**
  - *Transferred from CyGuide Engine Core*
  - Explicit memory sanitization (`wipe_credentials()`, secure memory buffers) upon process and task finalization, preventing residual keys from lingering in Python heap or core dumps.
- [ ] **Packaging & PyPI Readiness:** Clean wheel builds with `uv build` and zero external C dependencies.

---

### Epoch 2: The Agent Telemetry Protocol (MCP & Zero-Token Diffs)
*Target: v0.3.0*
*Focus: Turning Ether into the foundational operating system for Autonomous AI Security Agents.*

- [ ] **Native Model Context Protocol (MCP) Server (`ether.mcp`):**
  - Stdio and Server-Sent Events (SSE) server allowing Cursor, Claude Desktop, and LangGraph agents to drive security tools directly through structured MCP tools.
  - Core tools: `execute_tool`, `query_graph`, `get_diff`, `inspect_entity`, `abort_action`.
- [ ] **Deterministic Graph Diffing Engine:**
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
- [ ] **Embedded Offline Vector Memory & Finding RAG (`sqlite-vec`):**
  - *Transferred from CyGuide Engine Core*
  - Direct integration of `sqlite-vec` vector embeddings within SQLite.
  - Generates fast local vector embeddings for discovered services, banners, MITRE ATT&CK techniques, and CVE summaries.
  - Instant local semantic search and finding correlation with zero external API calls or network egress.
- [x] **Prompt Injection Defense Sandbox (`ether.core.sandbox`):**
  - Standardized `<untrusted_scan_output>` boundary tags with closing tag breakout neutralization (`</untrusted_scan_output>` converted to `<\/untrusted_scan_output>`).
  - Automatic redaction of private keys, authorization tokens, passwords, and API keys.
  - Active neutralization of adversarial prompt injection embedded inside HTTP headers, SSL certificates, and DNS TXT records.

---

### Epoch 3: High-Throughput Chained Execution & Pipeline DAG
*Target: v0.4.0*
*Focus: Multi-stage, high-concurrency reconnaissance pipelines.*

- [ ] **Chained Pipeline Engine (Unix Pipe Metaphor for Security):**
  - Allow declarative piping of security tools where findings from tool A automatically parameterize tool B:
    ```bash
    ether pipeline "subfinder(target=$DOMAIN) | dnspython | httpx | nuclei"
    ```
  - Graph-aware routing: output `network.host` findings automatically fan out into parallel port scans; discovered `network.service(http)` nodes automatically route to web fuzzers.
- [ ] **Native Packet Crafting & Stealth Network Engine (`scapy`):**
  - *Transferred from CyGuide Engine Core*
  - Pure-Python stealth TCP SYN scanning, custom port-knocking sequences, and local ARP network sniffing emitting typed `network.host` and `network.service` findings with zero external binary dependencies.
- [ ] **Worker Task Pool & Backpressure Concurrency:**
  - Scalable worker pool allowing 50+ concurrent background scans without event-loop starvation.
  - Dynamic disk spooling and chunk recycling keeping engine memory usage below **25 MB** under massive telemetry loads.
- [ ] **Streaming Pub/Sub Event Bus:**
  - Real-time event streaming (`asyncio.Queue` / WebSockets) emitting live findings as they are parsed, enabling external dashboards or remote TUIs to attach and detach seamlessly.
- [ ] **Continuous Telemetry, Metrics & Observability (`ether.telemetry`):**
  - Prometheus `/metrics` and OpenTelemetry structured telemetry exporters.
  - Runtime monitoring tracking subprocess execution latencies, backpressure queue depths, WAL checkpoint durations, and memory watermarks.
  - System health diagnostics (`DiagnosticEngine`) auditing file descriptor headroom (`ulimit -n`), disk write pressure, and engine invariants.

---

### Epoch 4: The Unrestricted "Beast" Engine (Offensive Workstation Core)
*Target: v0.5.0*
*Focus: Sovereign offensive operations, full PTY emulation, and exploit choreography.*

- [ ] **Dual-Path Interactive POSIX PTY Supervisor (`pyte` + `ptyprocess` / `os.openpty`):**
  - *Transferred from CyGuide Engine Core*
  - Dedicated OS pseudo-terminal pair (`master_fd`/`slave_fd`) allocation replacing `stdin=DEVNULL` for interactive tools (`msfconsole`, `gdb`, reverse shell listeners, `ssh`, `sudo`).
  - In-memory VT102/xterm screen emulation via `pyte` to track ANSI escape codes, cursor positions, color buffers, and screen diffs.
  - Forwarding terminal window resize signals (`SIGWINCH` via `fcntl.ioctl` with `termios.TIOCSWINSZ`).
  - Background loot & credential extraction from live interactive streams without interrupting the operator shell.
- [ ] **Enterprise Active Directory Protocol Engine (`impacket`):**
  - *Transferred from CyGuide Engine Core*
  - Python-native Active Directory assessment engine providing Kerberoasting, AS-REP roasting, and SMB/RPC interaction.
  - Emits typed findings (`ad.user`, `ad.spn`, `ad.ticket`, `ad.share`) directly into the target graph.
- [ ] **Metasploit Interactive PTY & RPC Bridge (`msfconsole`):**
  - *Transferred from CyGuide Engine Core*
  - Supervised PTY adapter for managing active Metasploit shells, meterpreter sessions, and payload handlers, normalizing output into the graph.
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
- [ ] **The "CyGuide" & "Beast" Ecosystem:**
  - CyGuide permanently re-based on top of `pip install ether`.
  - Independent release of the Beast Power Workstation utilizing Ether's full PTY and offensive capabilities.

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
| **UI Coupling** | High (terminal emulator) | High (Textual TUI) | **Zero (100% Headless Engine/Kernel)** |
| **Encrypted Archives** | GPG manual tar | None | **Argon2id + AES-256-GCM Authenticated SQLite** |
| **Vector Intelligence**| None | None | **In-Process `sqlite-vec` Semantic Embeddings** |

---

## Definition of Done for Core Milestones

To ensure high standards, no milestone in this roadmap is declared complete without:
1. **100% AST Invariant Proofs:** Zero unauthorized cross-layer or UI imports.
2. **Deterministic Mathematical Proofs:** Hypothesis property tests proving PIK uniqueness, idempotence, and Radix Trie correctness.
3. **Universal Hostile Fuzzing:** All adapters tested against truncated JSON, broken ANSI, and null bytes.
4. **Sub-10s Test Run:** Full regression suite executing in under 10 seconds locally.
