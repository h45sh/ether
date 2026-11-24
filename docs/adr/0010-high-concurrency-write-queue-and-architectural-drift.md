# ADR 0010: High-Concurrency Async Write Serialization, Dynamic Preflight Gates, and Architectural Drift Engine

## Status
Accepted

## Context
Following the empirical multi-agent AWS evaluation and live performance critiques documented in Epoch 3, Section 4 ([ROADMAP.md#L188-L215](file:///home/harsh/Documents/ether/ROADMAP.md#L188-L215)), several core substrate bottlenecks and ergonomic friction points were identified across concurrent execution, gateway preflight, fuzzer output hygiene, and telemetry diagnostics:

1. **SQLite WAL Write Lock Contention Under Multi-Agent Concurrency:**
   While SQLite in WAL mode permits multiple concurrent readers, database writes are strictly serialized. When 50+ autonomous subagents execute parallel actions writing findings to `~/.ether/ether.db`, tasks trigger `sqlite3.OperationalError: database is locked` despite `busy_timeout` configurations. A high-leverage architectural solution is required to serialize writes cleanly without starving readers.

2. **Brittle Static Categorization in the Action Gateway:**
   `preflight.py` relied on hardcoded static sets (`WEB_TOOLS`, `NETWORK_TOOLS`) and rigid URL regex validations. This violated the **Smart Adapter / Simple Core** principle, requiring core gateway modifications whenever new tools were introduced and rejecting valid hybrid targets (e.g. `http_probe` accepting bare IPs or hostnames).

3. **Web Fuzzer Graph Pollution & Missing 404 Baseline Calibration:**
   Web fuzzers (`ffuf`, `gobuster`) hitting servers with custom 404 handlers or wildcard 200 responses flooded the entity graph with thousands of synthetic findings. Fuzzers lacked an automated mechanism to discover baseline response geometry and synthesize negative filter flags (`-fs`, `-fw`).

4. **Absence of Native Architectural Drift Auditing:**
   Autonomous agents and CI/CD pipelines lacked a deterministic mechanism to compare observed graph state against expected ground-truth architecture specifications, hindering automated regression detection and compliance verification.

5. **Opaque MCP Tool Failures & Lack of Error Taxonomy:**
   MCP tool execution failures frequently manifested as masked generic empty findings or unhandled JSON-RPC protocol exceptions, preventing autonomous agents from performing structured self-healing.

6. **CLI Argument Asymmetry:**
   Subcommands required either strict positional arguments or strict options, creating syntax invocation errors for autonomous agents alternating between parameter formulations.

7. **Cryptographic TLS & Cipher Suite Blindness:**
   Ether lacked structured TLS certificate and cipher suite finding schemas, requiring external ad-hoc scripts to audit protocol deprecation and certificate expiry.

---

## Decision

### Part 1: High-Concurrency Async Write Serialization Queue (`GraphStore`)
We introduce an internal, single-writer asynchronous serialization queue in `GraphStore`:
1. **Queue Architecture:** An in-memory `asyncio.Queue` buffers pending write operations (`upsert_finding`, `create_session`, `record_event`).
2. **Dedicated Writer Worker:** A single persistent background worker task drains the queue using a dedicated write connection.
3. **Adaptive Transaction Batching:** The worker batches pending write operations—committing either every 50 operations or every 25ms window inside a single `BEGIN IMMEDIATE ... COMMIT` block—increasing write throughput by up to 20x.
4. **Immediate Future Resolution:** Each enqueued operation is paired with an `asyncio.Future`, ensuring callers receive immediate completion or error notifications with full sequential consistency.
5. **Read Connection Pool:** Read queries acquire connections from an async reader pool configured with `PRAGMA query_only = ON;` and `busy_timeout = 5000`.
6. **Graceful Teardown:** `GraphStore.close()` drains all pending queue operations and resolves all outstanding futures before closing the write connection.

### Part 2: Dynamic Adapter-Driven Preflight Gate (`ether.gateway.preflight`)
We eliminate all static tool categorization dictionaries from `preflight.py`:
1. **Manifest Contract:** Tool adapters declare valid target formats in `manifest.toml` via `target_types = ["url", "ip", "cidr", "domain"]`.
2. **Schema Introspection:** `preflight.py` dynamically queries the tool's manifest and `target_schemas` to validate target strings against standard IP/CIDR/URL parsing primitives.
3. **Zero-Heuristic Dispatch:** New tool adapters registered in `tools/` automatically inherit schema-compliant target validation with zero modifications to gateway code.

### Part 3: Automated Fuzzer Baseline Calibration
We encapsulate response calibration entirely inside web fuzzer tool adapters (`FfufAdapter`, `GobusterAdapter`):
1. **Synthetic Nonce Probe:** Before launching wordlist traversal, the adapter dispatches an out-of-band probe to `/.ether_probe_<nonce>` via async HTTP.
2. **Negative Filter Synthesis:** If the server returns a uniform response (e.g. static 200 with identical length or word count), the adapter dynamically injects negative filter flags (`-fs <size>` or `-fw <words>`).
3. **Fail-Open Semantics:** If the target drops the connection, rate-limits, or times out during calibration, the adapter logs a diagnostic warning and proceeds with uncalibrated execution rather than halting the workflow.

### Part 4: Native Architectural Drift Engine (`ether.drift`)
We implement a native architectural drift auditing subsystem:
1. **Baseline Specification:** Ground-truth architectures are specified using native finding schemas (`NetworkHost`, `NetworkService`, `WebEndpoint`), enabling deterministic PIK-to-PIK matching.
2. **Evaluation Modes:**
   - `topology` (default): Audits presence/absence of expected hosts, open ports, and web endpoints.
   - `strict`: Additionally flags differences in service versions, software banners, and missing mandatory HTTP security headers.
3. **Normalized Metric & Graph Nodes:** Computes a normalized scalar drift score $D \in [0.0, 1.0]$ and records discrepancy nodes as typed `audit.drift` findings in the session graph.
4. **Surfaces:** Exposes CLI commands `ether drift audit <session_id> --baseline <file>` and `ether drift export-baseline <session_id> --out <file>`, along with an MCP supervisory tool `audit_drift`.

### Part 5: High-Fidelity MCP Error Diagnostics
We restructure MCP execution error handling:
1. **Structured Telemetry Payload:** Execution failures return a structured error dictionary containing `exit_code`, `stderr_snippet`, `error_category`, and `is_error=True`.
2. **Standardized Error Taxonomy:** Uses a fixed enum: `TARGET_UNREACHABLE`, `COMMAND_TIMEOUT`, `BINARY_MISSING`, `NON_ZERO_EXIT`, `SCOPE_BLOCKED`.
3. **Protocol Stability:** JSON-RPC connections remain open and healthy, allowing autonomous agents to parse error categories and execute corrective logic.

### Part 6: Hermetic In-Tree Semantic Vector Embeddings Seam
We establish a two-tier vector embedding strategy in `src/ether/common/embeddings.py`:
1. **Base Tier (Zero-Dependency):** Deterministic 384-dimensional feature hashing with SHA-256 projections, subword n-grams, and L2 normalization executes in <1ms without third-party libraries.
2. **Accelerated Tier (ONNX Runtime):** Dynamically promotes to an in-tree quantized `all-MiniLM-L6-v2` ONNX model (~22MB) when `onnxruntime` is available, maintaining full offline operation.

### Part 7: Dedicated Cryptographic TLS Finding Schemas & Dual-Path Prober
We add dedicated TLS finding schemas in `src/ether/schemas/network.py`:
1. **Schemas:**
   - `TlsCertificate` (`tls.certificate`): Subject, issuer, SANs, validity window, key algorithm, key size, and SHA-256 fingerprint.
   - `TlsCipherSuite` (`tls.cipher_suite`): Negotiated protocol version, cipher suite name, PFS status, and deprecation flag.
2. **Dual Execution:** Native Tier A async coroutine `tools/tls_probe/` performs zero-fork TLS handshakes; Tier B `tools/sslyze/` executes deep vulnerability sweeps when requested.

### Part 8: CLI Argument Router Pre-Normalization
`src/ether/cli/router.py` implements a pre-normalization pass that maps positional values and `--flag` options interchangeably before dispatch, guaranteeing 100% parameter symmetry across all subcommands.

---

## Consequences

### Positive
- **Contention-Free Database Concurrency:** Single-writer queue eliminates SQLite WAL write locks across 50+ concurrent agents.
- **Architectural Purity:** Action gateway is fully decoupled from tool names and static categorizations.
- **Graph Hygiene:** Web fuzzers no longer pollute the entity graph with false-positive wildcard endpoints.
- **Continuous Compliance:** Instant architectural drift scoring against ground-truth baselines via CLI and MCP.
- **Agent Ergonomics:** Standardized MCP error taxonomy and CLI argument symmetry streamline autonomous tool use.
- **Headless Invariant Preserved:** Zero UI code, zero external network calls for vector embeddings, and full backward compatibility.

### Negative / Trade-offs
- In-memory write queue introduces up to 25ms batch latency for write confirmation under high load.
- Background worker requires careful cancellation protection during process teardown.
- Quantized ONNX weights add ~22MB to optional asset distributions if bundled.
