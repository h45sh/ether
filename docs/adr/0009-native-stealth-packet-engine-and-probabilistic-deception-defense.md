# ADR 0009: Native Stealth Packet Engine and Probabilistic Deception Defense

## Status
Accepted

## Context
In Epoch 3, Section 3 ("Execution Pipeline DAG & Substrate Mechanics"), Ether established chained reactive execution, scalable worker pools, streaming event buses, and continuous observability. However, two critical mechanical capabilities remained unaddressed:

1. **Absence of In-Process Layer 2/3/4 Packet Crafting:**
   Security operations frequently require stealth TCP SYN sweeps, custom port-knocking authentication sequences, and local ARP discovery. Previously, Ether relied exclusively on external compiled binaries (`nmap`, `masscan`, `rustscan`). While effective, spawning external processes for fast, single-probe operations introduces OS fork overhead, fails in minimal container environments lacking compiled binaries, and prevents programmatic, low-level socket manipulation. Furthermore, raw socket packet crafting (`SOCK_RAW`) mandates `CAP_NET_RAW` or root (`UID 0`), creating fragile execution failures in unprivileged environments.

2. **Vulnerability to Active Deception and Tarpits:**
   Autonomous agents and automated scanner pipelines operate under the assumption that open ports and banner strings represent genuine services. Defensive systems deploy honeypots (e.g., Cowrie, Dionaea), tarpits (e.g., LaBrea delaying TCP window acknowledgments or emitting single bytes every 10 seconds), and port-sprawl moving-target defenses (MTDs) returning SYN-ACK on all 65,535 ports. These defenses exhaust agent token budgets, induce event-loop timeouts, and bloat the target graph with thousands of synthetic nodes.

To complete Epoch 3, Section 3 ([ROADMAP.md#L173-L177](file:///home/harsh/Documents/ether/ROADMAP.md#L173-L177)), Ether requires a native, pure-Python stealth packet crafting engine and a robust two-tier deception defense subsystem that preserves Ether's strict headless invariants, deep module architecture, and Tier 1 Frozen Core schema stability.

---

## Decision

### Part 1: Native Packet Crafting & Stealth Network Engine (`tools/stealth_scan/`)

We introduce a deep, pluggable Tier A in-process `ToolAdapter` at `tools/stealth_scan/` conforming to the [ADR 0004](file:///home/harsh/Documents/ether/docs/adr/0004-unified-dual-execution-adapter-seam.md) dual-execution protocol (`execute_action()`).

1. **Dependency Isolation & Fast CLI Startup Latency:**
   - `scapy>=2.5.0` is declared as an official dependency in `pyproject.toml`.
   - **Strict Lazy-Import Invariant:** `scapy` modules (`scapy.all`, `scapy.layers.inet`, `scapy.layers.l2`) are never imported at top-level package initialization. Imports are strictly deferred to runtime execution inside `tools/stealth_scan/adapter.py`. This guarantees top-level CLI commands (`ether --help`) and Tier 0 unit tests consistently execute within the mandatory `<100ms` latency threshold.

2. **Privilege Boundary Detection & Graceful Fallback:**
   - The adapter performs runtime privilege detection by testing raw socket allocation (`socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)`) and `CAP_NET_RAW` availability.
   - **Privileged Execution (Raw Sockets):** Crafts raw IP/TCP packets via Scapy:
     - Half-open TCP SYN scanning without completing the 3-way handshake (avoiding application-layer connection logging).
     - Layer 2 ARP broadcast sweeps for fast local host discovery.
     - Multi-stage port-knocking packet trains (custom TCP/UDP port sequences with configurable inter-packet delays).
   - **Unprivileged Graceful Fallback (`asyncio`):** When running in unprivileged Docker containers, Kubernetes pods, or restricted non-root user shells, the adapter automatically degrades to non-blocking `asyncio.open_connection()` half-open/connect sweeps with rate limiting.
   - **Schema Normalization:** Regardless of execution path (Scapy vs unprivileged fallback), the adapter emits identical normalized `NetworkHostFinding` and `NetworkServiceFinding` schemas.

3. **Unified Interface & Parameter Contracts (`manifest.toml`):**
   - The tool is parameterized via a single deep interface rather than fragmented shallow directories:
     - `mode`: `"syn"` (default) | `"arp"` | `"knock"`
     - `ports`: Comma-separated or dash-ranged port list (e.g. `"22,80,443,8000-8080"`).
     - `knock_sequence`: Array of integer ports for knocking (e.g. `[7000, 8000, 9000]`).
     - `interface`: Optional network interface name (e.g. `"eth0"`).
     - `rate_limit`: Token-bucket packet pacing rate (default: `500` packets per second) to prevent OS buffer drops and kernel interface saturation.

4. **Scope & Routing Enforcement:**
   - `mode="arp"` strictly validates that target ranges belong to the local broadcast subnet / RFC1918 CIDR. Non-local routed internet targets are rejected with a deterministic validation error.
   - All targets are validated against `ActionGateway`'s engagement CIDR scope under `GatePolicy.SAFE`.

---

### Part 2: Probabilistic State Estimation & Deception Defense

We deploy a two-tier defense mechanism that protects both execution runtime resources and knowledge graph integrity:

1. **Tier 1: Inline Stream Anomaly Guard (`executor.py` / `LogSpooler`):**
   - Stream processing loops monitor inter-chunk timing deltas and token repetition.
   - **Tarpit Heuristic:** If a service emits sub-byte trickle streams (e.g. single bytes at >5s intervals) or enters infinite repetitive banner loops exceeding 15 seconds without finding progress, the stream guard immediately signals early termination (`SIGTERM` / task cancellation).
   - An execution event records the target as an active tarpit (`is_tarpit = 1`), preventing event-loop starvation and pipeline blockages.

2. **Tier 2: Analytical Bayesian Belief Engine (`src/ether/graph/analytics.py`):**
   - Implemented within `GraphAnalyticsEngine` to compute finding legitimacy confidence ($0.0 \le \text{confidence} \le 1.0$) and classify honeypot deception.
   - **3-Factor Evidence Model:**
     - **Factor A (Port Distribution Entropy):** Evaluates the distribution of open ports on target hosts. If a host reports an abnormal volume of open ports (>500 ports) exhibiting uniform banner sizes or identical TTLs, the deception probability approaches 1.0 ($P(\text{honeypot}) > 0.95$).
     - **Factor B (Banner Signature Heuristics):** Identifies known honeypot fingerprints (e.g. Cowrie/Kippo SSH string offsets, Dionaea SMB emulators, fake HTTP server headers).
     - **Factor C (Cross-Tool Corroboration):** Reinforces confidence when findings are corroborated across independent tools and protocols (e.g. port confirmed by both SYN sweep and `http_probe` receives confidence $\ge 0.95$, while single-probe uncorroborated anomalies receive lower belief scores).

3. **Storage & Tier 1 Schema Preservation (`GraphStore`):**
   - In accordance with the Tier 1 Frozen Core policy, `src/ether/schemas/base.py` and `BaseFinding` remain strictly unmodified.
   - Belief states and deception classifications are persisted in a dedicated SQLite overlay table within `GraphStore`:
     ```sql
     CREATE TABLE IF NOT EXISTS node_beliefs (
         node_id TEXT PRIMARY KEY,
         session_id TEXT NOT NULL,
         confidence REAL NOT NULL DEFAULT 1.0,
         is_honeypot INTEGER NOT NULL DEFAULT 0,
         is_tarpit INTEGER NOT NULL DEFAULT 0,
         indicators TEXT NOT NULL DEFAULT '[]',
         updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
         FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
     );
     CREATE INDEX IF NOT EXISTS idx_node_beliefs_session ON node_beliefs(session_id);
     ```
   - **Evaluation Lifecycle:** Belief evaluation is executed on-demand or at session checkpoints via `GraphAnalyticsEngine.evaluate_deception(session_id)`, decoupling CPU-bound Bayesian calculations from high-throughput streaming ingestion.

---

### Part 3: Operational Interfaces & Operator Visibility

1. **CLI Commands:**
   - `ether graph belief <session_id>`: Displays tabular belief scores, honeypot classifications, and active tarpits for an engagement session.
   - `ether pipeline`: Supports direct chaining with the stealth scanner:
     ```bash
     ether pipeline "stealth_scan(target='192.168.1.0/24', mode='syn', ports='22,80,443') | http_probe | nuclei"
     ```

2. **Native MCP Server Tool:**
   - Exposes `get_deception_report(session_id: str)` returning:
     - `flagged_honeypots`: List of nodes with $P(\text{honeypot}) \ge 0.80$ and their matching heuristics.
     - `active_tarpits`: List of endpoints caught by the inline stream watcher.
     - `low_confidence_findings`: Findings lacking multi-tool corroboration.

---

## Consequences

### Positive
- **Complete In-Process Arsenal:** Pure-Python SYN scanning and port knocking eliminate external binary dependencies (`nmap`, `masscan`) for core reconnaissance workflows.
- **Headless Invariant Upheld:** Automatic fallback from raw Scapy sockets to non-blocking `asyncio` connect sweeps guarantees zero crashes across non-root containers and CI runners.
- **Agent Self-Healing:** Autonomous AI agents querying `get_deception_report` avoid wasting tokens or crafting exploit chains against synthetic honeypots.
- **Architectural Depth & Schema Stability:** The `node_beliefs` overlay table provides rich probabilistic state without mutating immutable node identity hashes (PIKs) in `src/ether/schemas/base.py`.

### Trade-offs & Mitigations
- **Scapy Package Footprint:** Scapy increases virtual environment size by ~35MB. 
  *Mitigation:* Strict runtime lazy-importing guarantees top-level CLI commands and unit tests maintain sub-100ms startup latency.
- **Asynchronous Bayesian Computation:** Post-scan evaluation means newly ingested nodes temporarily default to `confidence = 1.0` until `evaluate_deception()` runs.
  *Mitigation:* Inline stream guards catch immediate execution tarpits synchronously; full graph-wide Bayesian belief passes run automatically at session checkpoints.
