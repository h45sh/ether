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

---

## The Five Evolutionary Epochs

```
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
- [x] **Comprehensive Regression Suite:** 166 unit and integration tests passing in <10s.
- [ ] **Lightweight Headless CLI (`ether`):**
  - `ether run <tool> <target> [--json]`
  - `ether graph list-nodes <session_id>`
  - `ether graph export <session_id> -o out.db`
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
- [ ] **Prompt Injection Defense Sandbox:**
  - Standardized `<untrusted_scan_output>` boundary tags with closing tag breakout neutralization (`</untrusted_scan_output>` converted to `<\/untrusted_scan_output>`).
  - Active detection of adversarial prompt injection embedded inside HTTP headers, SSL certificates, and DNS TXT records.

---

### Epoch 3: High-Throughput Chained Execution & Pipeline DAG
*Target: v0.4.0*
*Focus: Multi-stage, high-concurrency reconnaissance pipelines.*

- [ ] **Chained Pipeline Engine (Unix Pipe Metaphor for Security):**
  - Allow declarative piping of security tools where findings from tool $A$ automatically parameterize tool $B$:
    ```bash
    ether pipeline "subfinder(target=$DOMAIN) | dnspython | httpx | nuclei"
    ```
  - Graph-aware routing: output `network.host` findings automatically fan out into parallel port scans; discovered `network.service(http)` nodes automatically route to web fuzzers.
- [ ] **Worker Task Pool & Backpressure Concurrency:**
  - Scalable worker pool allowing 50+ concurrent background scans without event-loop starvation.
  - Dynamic disk spooling and chunk recycling keeping engine memory usage below **25 MB** under massive telemetry loads.
- [ ] **Streaming Pub/Sub Event Bus:**
  - Real-time event streaming (`asyncio.Queue` / WebSockets) emitting live findings as they are parsed, enabling external dashboards or remote TUIs to attach and detach seamlessly.

---

### Epoch 4: The Unrestricted "Beast" Engine (Offensive Workstation Core)
*Target: v0.5.0*
*Focus: Sovereign offensive operations, full PTY emulation, and exploit choreography.*

- [ ] **True POSIX PTY Supervisor (`ether.core.pty`):**
  - Supervised pseudo-terminal allocation for interactive offensive tools (`msfconsole`, `gdb`, reverse shell listeners).
  - Clean VT100 / ANSI escape sequence sanitization that preserves raw operator interactivity while continuously extracting credentials and tokens in the background.
- [ ] **Attack Graph Traversal & Path Discovery:**
  - In-memory graph analytics algorithms:
    - Shortest path from unauthenticated Internet asset to Domain Admin / Root.
    - Lateral movement candidate identification based on shared credentials or open internal ports.
- [ ] **Autonomous Operation Daemon (`etherd`):**
  - Long-running headless daemon managing continuous surface monitoring, cron-scheduled re-scans, and alerting on state changes.

---

### Epoch 5: Distributed Sovereign Mesh & Global Telemetry
*Target: v1.0.0+*
*Focus: Multi-node distributed operations, zero-trust coordination, and plugin marketplace.*

- [ ] **Zero-Copy Distributed Graph Federation:**
  - Synchronization of multiple Ether nodes across VPSs, local networks, and cloud instances using SQLite session replication (CRDT / SQLite Session Extension).
  - Red-team operators share a live, unified target graph without a centralized server.
- [ ] **Pluggable WebAssembly (Wasm) Parser Sandboxing:**
  - Execute third-party community adapters in lightweight Wasm sandboxes, ensuring community tool parsers can never compromise the host machine.
- [ ] **The "CyGuide" & "Beast" Ecosystem:**
  - CyGuide permanently re-based on top of `pip install ether`.
  - Independent release of the Beast Power Workstation utilizing Ether's full PTY and offensive capabilities.

---

## Concrete Capability Comparison

| Dimension | Raw Bash / Scripts | Current CyGuide | **Ether Engine (Ideal State)** |
| :--- | :--- | :--- | :--- |
| **Execution Safety** | Unrestricted / Fragile | Safe Lab Policy Only | **Pluggable (`SAFE` vs `UNRESTRICTED`)** |
| **Output Handling** | Ephemeral stdout | UI Ring Buffers | **64KB Spooled Disk + Bounded Memory Rings** |
| **State Storage** | Flat text files / logs | SQLite GraphStore | **Deterministic Multi-Session Graph + Event Sourcing** |
| **AI Agent Support** | Context bloat / Failures | None (Tutor only) | **Native MCP Server + Token-Zero Graph Diffs** |
| **Tool Orchestration** | Fragile bash pipes | Manual single-shot | **Automated Reactive DAG Pipelines** |
| **Interactive Shell** | Raw OS terminal | Non-PTY stream | **Supervised PTY with Background Extraction** |
| **UI Coupling** | High (terminal emulator) | High (Textual TUI) | **Zero (100% Headless Engine/Kernel)** |

---

## Definition of Done for Core Milestones

To ensure high standards, no milestone in this roadmap is declared complete without:
1. **100% AST Invariant Proofs:** Zero unauthorized cross-layer or UI imports.
2. **Deterministic Mathematical Proofs:** Hypothesis property tests proving PIK uniqueness, idempotence, and Radix Trie correctness.
3. **Universal Hostile Fuzzing:** All adapters tested against truncated JSON, broken ANSI, and null bytes.
4. **Sub-10s Test Run:** Full regression suite executing in under 10 seconds locally.
