# Ether Engineering Roadmap: From Core Substrate to Flagship Runtime

This document specifies the authoritative engineering milestones, architectural phases, quality gates, and deliverables for **Ether**.

---

## 🎯 The Core Vision

Ether is designed to be the **universal runtime and telemetry substrate for cybersecurity tooling and autonomous security agents** (analogous to the role the Linux kernel plays for userland distributions).

It decouples:
- **Execution & Normalization (Ether Engine)** $\to$ Pluggable tool adapters, streaming supervisors, deterministic graph storage, and policy gates.
- **Consumer Distributions** $\to$ Educational labs (`CyGuide`), offensive red-team workstations (`Beast`), and autonomous AI pentesting agents (`MCP / RPC`).

---

## 🗺️ Staged Roadmap & Milestones

### Phase 1: Engine Foundation & Mechanical Hardening (Current)
*Target: v0.1.0 – v0.2.0*
- [x] Initial repository decoupling at `/home/harsh/Documents/ether`.
- [x] Clean removal of all UI/Textual/presentation dependencies.
- [x] Re-homing of core packages: `ether.core`, `ether.graph`, `ether.gateway`, `ether.registry`, `ether.schemas`.
- [x] Pluggable `GatePolicy` seam (`SAFE` vs `UNRESTRICTED` Beast mode).
- [x] Universal adapter fuzzing suite (11 adapters verified against adversarial streams).
- [ ] **Comprehensive Test Migration:** Port `test_timeline.py`, `test_engine_store.py`, `test_gateway.py`, and `test_properties.py`.
- [ ] **AST Architectural Guard:** Write `tests/unit/test_architecture.py` to mechanically fail if any `textual`, `cyguide.ui`, or unauthorized cross-layer imports enter `ether`.
- [ ] **CLI Driver:** Implement lightweight headless CLI (`ether run <tool> <target>`, `ether query <session>`).

---

### Phase 2: Autonomous Agent Protocol & Telemetry Streaming (v0.3.0)
*Target: AI Agent Interoperability & Zero-Token-Waste Context*
- [ ] **Native Model Context Protocol (MCP) Server:**
  - Build `ether.mcp` enabling any LLM client (Claude Desktop, Cursor, LangChain, AutoGen) to connect directly to Ether via stdio/SSE.
  - Expose tools: `ether_scan`, `ether_graph_query`, `ether_diff`, `ether_execute`.
- [ ] **Deterministic Graph Diffing:**
  - Return compact JSON deltas to agents after tool runs (e.g. `{"new_hosts": 1, "new_ports": [80, 443]}`) instead of dumping thousands of raw lines into the LLM context window.
- [ ] **Prompt Injection Sanitizer:**
  - Standardized `<untrusted_scan_output>` wrapper and tag-breakout neutralizer for all AI-facing outputs.

---

### Phase 3: High-Performance Execution & Parallelism (v0.4.0)
*Target: Enterprise Throughput & Multi-Target Orchestration*
- [ ] **Async Task Group / Worker Pool:**
  - Concurrent execution of multi-stage tool chains: `subfinder` $\to$ `httpx` $\to$ `nuclei` pipeline execution.
- [ ] **SQLite Concurrency & WAL Checkpoint Tuning:**
  - Optimize SQLite WAL checkpointing and batch finding upserts to sustain 50,000+ entities/sec without database lock contention.
- [ ] **Streaming Event Subscriptions:**
  - In-memory Pub/Sub event bus (`asyncio.Queue` / WebSockets) so external TUIs, dashboards, or distributed agents can subscribe to real-time finding feeds.

---

### Phase 4: Beast Mode & The Offensive Workstation (v0.5.0)
*Target: The Ultimate Power Operator Substrate*
- [ ] **Unrestricted PTY / Interactive Terminal Seam:**
  - Real POSIX PTY proxy in `ether.core.pty` allowing interactive utilities (`msfconsole`, reverse shells, `gdb`) to run supervised with full terminal escape sequence handling.
- [ ] **Chained Attack Graph Traversal:**
  - Built-in graph algorithms for automated attack path finding (e.g. `Host` $\to$ `Open Port 445` $\to$ `SMB Signing False` $\to$ `Credential Hash` $\to$ `Admin Compromise`).
- [ ] **Headless Daemon Mode:**
  - Background daemon (`ether daemon`) running multi-hour continuous reconnaissance and asset tracking.

---

### Phase 5: Consumer Integration & Ecosystem (v1.0.0)
*Target: Production Stability & PyPI Distribution*
- [ ] **CyGuide Dependency Update:**
  - Refactor `cyguide` to depend on `ether` via `pip install ether`. CyGuide becomes purely a pedagogical TUI frontend on top of Ether.
- [ ] **Standalone Beast Workstation App:**
  - High-velocity keyboard-driven power workstation consuming Ether.
- [ ] **PyPI Official Release:**
  - Publish `ether` to PyPI.

---

## 🛡️ Non-Negotiable Engineering Standards

1. **Zero UI Code:** Ether must compile and run on headless servers, containers, and minimal Linux environments without X11, Wayland, or TUI libraries.
2. **Review Proof, Not Code:** Every pull request and release must provide automated test proofs (`pytest -m tier0`, `pytest -m fast`, `pytest -m fuzz`).
3. **Hermetic Test Isolation:** Tests never pollute host configuration or user home directories.
4. **Pure Argument Vectors:** Never invoke `shell=True`. Never leak operator credentials across process boundaries.
