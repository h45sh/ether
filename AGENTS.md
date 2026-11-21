# Ether Agent Directives, Engineering Standards & Architecture Rules

This authoritative specification governs all AI agents and contributors working in the **Ether** repository.
Adherence to these mechanical standards is mandatory to preserve architectural depth, concurrency guarantees, security isolation, and headless predictability.

---

## 1. Project Mission & Identity

**Ether** is a headless, reactive process supervisor, AST validator, and deterministic graph telemetry engine for cybersecurity tooling and autonomous AI agents.

- **Strict Headless Invariant:** Ether contains **zero UI code, zero Textual imports, and zero presentation widgets**. Ether is an engine/kernel, not an application.
- **Smart Adapter / Simple Core:** Ether is tool-agnostic. Pluggable tool adapters (`tools/<name>/`) encapsulate CLI argument construction, binary discovery, and stream parsing into normalized Pydantic schemas.
- **Deterministic State Machine:** All entities discovered (hosts, services, vulnerabilities, credentials) are indexed via deterministic SHA-256 Primary Identity Keys (PIK) into an immutable, event-sourced SQLite graph.

---

## 2. Context Gate & Token Optimization Policy

1. **Slice Reads:** When inspecting code, use line-bounded ranges (`read_file` with `StartLine` and `EndLine`) targeting only the relevant function or block. Never dump full files into context unprompted.
2. **Tier 0 Local Pre-flight:** Run zero-cost local checks (`.venv/bin/ruff check .`, `.venv/bin/pytest -m tier0`) in <100ms before multi-step agent reasoning loops.
3. **High-Density Technical Communication:** Omit conversational filler, repeating user prompts, or speculative essays. Focus strictly on concrete technical diffs, mechanical proofs, and verified commands.

---

## 3. Architectural Principles: Deep Modules over Shallow Wrappers

Ether strictly adheres to John Ousterhout’s philosophy of software design (**Deep Modules** over Shallow Modules):

1. **Deep Modules (Small Interface, Big Implementation):**
   - Every module must provide a concise, high-leverage interface that hides significant internal complexity.
   - **Never create shallow classes or functions:** Avoid wrappers that simply pass arguments 1:1, thin helper classes with an interface as complex as their implementation, or single-method shims.
   - Modules like `ExecutionSession`, `ActionGateway`, `GraphStore`, and `ToolRegistry` are deep; do not split them into trivial micro-files.
2. **Strict Encapsulation & Information Hiding:**
   - Encapsulate private state, helper functions, and internal connection objects.
   - **Never leak private attributes** across architectural boundaries (e.g. no caller should access `_active_processes`, `_sessions`, or internal connection pools).
3. **Unidirectional Layer DAG:**
   Dependencies flow strictly downwards in one direction:
   ```
   Headless Interfaces (SDK / CLI / MCP Server: ether/__init__.py, ether/cli.py)
     ↓
   Gateways & Policy (ether/gateway/gate.py, network.py)
     ↓
   Core Process Supervision & Execution (ether/core/session.py, executor.py)
     ↓
   State & Graph Storage (ether/graph/store.py, timeline.py)
     ↓
   Pluggable Tool Adapters & Registry (ether/registry/registry.py, adapter.py, tools/*)
     ↓
   Normalized Schemas & Primitives (ether/schemas/*, ether/common/*)
   ```

---

## 4. Concurrency, Streaming & Performance Guarantees

1. **Process Isolation & Pure Argument Vectors:**
   - **NEVER use `shell=True`**, `os.system()`, or string formatting to build shell commands.
   - Always spawn binaries via argument vectors (`List[str]`) using `asyncio.create_subprocess_exec(cmd[0], *cmd[1:], ...)`.
2. **High-Throughput Ring Buffers & Disk Spooling:**
   - Tools can produce gigabytes of terminal noise. Stream raw output directly to disk (`data/logs/{action_id}.log`) using `LogSpooler` with 64KB buffering.
   - Maintain bounded memory ring buffers (`collections.deque(maxlen=5000)`) in runtime sessions to guarantee RAM usage remains strictly capped (<10MB per active job).
3. **Event Loop Starvation Defense:**
   - Explicitly yield control to the asyncio event loop in tight streaming loops:
     - `await asyncio.sleep(0.01)` inside process stream reader loops.
4. **Environment Secret Scrubbing:**
   - Always scrub child process environments with `sanitize_subprocess_env()`: strip `ETHER_*`, `CYGUIDE_*`, `OPENAI_*`, `ANTHROPIC_*`, `GROQ_*`, `DEEPSEEK_*`, `AWS_*`, `GITHUB_*`, `VAULT_TOKEN`, and SSH keys. Child tools must never inherit host secrets.

---

## 5. Security & Policy Seams: Safe vs. Unrestricted (Beast Mode)

Ether features a first-class `GatePolicy` seam:

```python
class GatePolicy(str, Enum):
    SAFE = "safe"                  # Enforces SSRF defense, CIDR scope boundary, blocks metadata
    UNRESTRICTED = "unrestricted"  # Beast mode: allows raw execution, any target, unrestricted shell
```

1. **Under `GatePolicy.SAFE` (Default for public/educational consumers like CyGuide):**
   - Strictly blocks cloud metadata targets (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`).
   - Validates targets against authorized engagement CIDR scopes.
   - Disallows arbitrary autonomous shell commands (`!` prefix reserved for authenticated manual users).
2. **Under `GatePolicy.UNRESTRICTED` (Used by Offensive Workstations & Power Red-Teams):**
   - Bypasses destination firewall for authorized red-team engagements.
   - Allows full-spectrum command execution and raw PTY pass-through without artificial gates.
3. **Prompt Injection Boundary:**
   - Untrusted target outputs passed to AI systems must be wrapped inside `<untrusted_scan_output>...</untrusted_scan_output>` XML boundary tags with closing tag breakout neutralization (`</untrusted_scan_output>` replaced with `<\/untrusted_scan_output>`).

---

## 6. Data Modeling & Storage (GraphStore & SQLite)

1. **Primary Identity Keys (PIK):**
   - Every entity finding inherits from `BaseFinding` in `ether.schemas.base`.
   - Node IDs are deterministic SHA-256 hashes of `(schema_type + sorted_pik)`.
2. **Idempotent Upsert & Non-Destructive Merging:**
   - Upserting findings merges attributes rather than creating duplicate nodes.
   - Relational edges (`parent_id`, `associations`) are automatically wired.
3. **Immutable Event Sourcing:**
   - Every action and result is recorded into an append-only `event_log` table for forensic replay and verification.
4. **Hardened SQLite Engine:**
   - 100% parameterized SQL queries (`?`). Never format strings into SQL.
   - Enforce `PRAGMA foreign_keys = ON;`, `PRAGMA journal_mode = WAL;`, and `busy_timeout = 5000` on every connection.

---

## 7. Testing Standards & Mechanical Verification

Ether adheres to the **"Review Proof, Not Code"** engineering model:

1. **Mechanical Gates over Prose Prompts:**
   - Architectural invariants, layer boundaries, and AST checks are enforced by `pytest -m tier0`.
   - Core mathematical properties (PIK generation, canonicalization idempotence, Radix Trie prefix matching) are verified via property-based testing with **Hypothesis** (`tests/unit/test_properties.py`).
2. **Universal Adapter Fuzzing:**
   - Every tool adapter is tested against 4 adversarial streams (broken ANSI codes, 20,000-token strings, truncated JSON, and null bytes) in `tests/unit/test_parsers/test_fuzz_all_adapters.py`.
3. **Hermetic Test Isolation:**
   - Tests must never touch `~/.ether` or `~/.cyguide`. Always use `GraphStore(":memory:")` or temporary isolated fixture directories.
4. **Execution Matrix:**
   - `pytest -m tier0`: AST invariants, mathematical properties (<2s).
   - `pytest -m fast`: Fast in-memory process, graph, and gateway tests (<5s).
   - `pytest -m fuzz`: Universal security tool adapter fuzzing suite.
