# ADR 0015: Autonomous Agent Usability, Security Boundary & Memory Hardening (Epoch 3, Section 7)

## Status
Accepted (Design Specification)

## Context
Following the multi-agent Run 4 benchmark evaluation (`reports/run_4/`), comprehensive stress testing revealed 11 operational friction points, memory limit breaches, and security bypass vectors in the autonomous supervisory substrate:

1. **Memory Bound Breach on Heavy Streams:** `_job_buffers` bounded chunk count (`deque(maxlen=5000)`) instead of bytes. A 16.11 MB scanner flood caused a 33.49 MB peak RSS delta, violating the `<10 MB` memory cap.
2. **SSRF & DNS Rebinding Vulnerabilities:** `is_blocked_destination()` defaulted `allow_loopback=True` when `allowed_cidrs` was unset, and `ActionGateway`/`PreflightVerifier` omitted active DNS resolution, permitting magic domains (`*.nip.io`, `localtest.me`) to bypass `GatePolicy.SAFE`.
3. **Compound CLI Flag Smuggling:** Targets embedded in joined (`-u<target>`), colon-delimited (`--resolve=h:p:ip`), or comma-delimited (`--targets=a,b`) arguments bypassed target-only scope checks.
4. **Catastrophic ReDoS in Gobuster:** `GobusterAdapter.STATUS_PATTERN` suffered from $O(N^2)$ backtracking on long whitespace-free input lines.
5. **Subprocess Environment Secret Leakage:** `sanitize_subprocess_env()` leaked 11 of 20 tested secret variables (including `AWS_SESSION_TOKEN`, `AZURE_CLIENT_SECRET`, `SSH_AUTH_SOCK`, `DOCKER_PASSWORD`, `DATABASE_URL`).
6. **XML Prompt Injection Boundary Variants:** `sanitize_untrusted_output()` failed to neutralize closing tag variations with whitespace or attributes (`</untrusted_scan_output >`) and left opening tags unescaped.
7. **Insecure File & Directory Creation Modes:** `atomic_create_file()` retained `0o644` on overwrite, and `GraphStore` created directory trees with `0o755` instead of `0o700`.
8. **HTTP Tarpit Deadlines & Honeypot Blindness:** `http_probe` timed out per-read rather than cumulatively, stalling for 66s on slow-drip tarpits; Cowrie honeypot banners were dropped from service findings and graph deception scoring.
9. **Missing HTTP Visibility & Broken Target Schema:** `http_probe` omitted response body snippets and 302 redirects; `tls_probe` rejected `IP:PORT` targets as invalid domains.
10. **Disconnected Graph Edges:** `graph blast-radius` and `graph attack-path` failed because relational edges (`host` -> `service` -> `endpoint` -> `vulnerability`) were not wired automatically during upsert.
11. **CLI & SDK Ergonomic Inconsistencies:** `-j / --json` was ignored by most CLI subcommands, node IDs were truncated to 12 characters, and `ExecutionSession` lacked zero-boilerplate defaults.

## Decision

### 1. Byte-Bounded Buffers & Drop-Oldest Subscription Queues (`ether.core.session`)
- Replace `deque(maxlen=5000)` in `_job_buffers` with `ByteBoundedRingBuffer(max_bytes=2097152)` (2 MB per job limit).
- When buffer exceeds 2 MB, silently drop oldest chunks and increment `dropped_bytes_count`.
- In `subscribe()`, bound event queues to `asyncio.Queue(maxsize=100)`. On full queue, drop the oldest event to prevent producer deadlock and cap RSS memory growth.

### 2. Unified SSRF, DNS Resolution & Flag Smuggling Firewall (`ether.gateway`, `ether.common.scope`)
- Default `allow_loopback=False` under `GatePolicy.SAFE`, requiring explicit `EngagementScope(allow_loopback=True)`.
- Wire `ScopeValidator.check_destination()` with an async 1.0s DNS resolver into both `ActionGateway` and `PreflightVerifier`. Reject unresolvable domains under `SAFE` mode.
- Deconstruct all arguments in `--flags`, extract embedded host/URL/IP values, validate them against `ScopeValidator`, and reject shell metacharacters (`|`, `;`, `&`, `$`, `` ` ``, `\n`) under all policies.

### 3. Linear-Time Gobuster Stream Parser (`tools/gobuster/adapter.py`)
- Pre-filter lines with `if " (Status:" in line:`.
- Enforce a 4,096-character per-line safety cap.
- Parse status codes via `line.partition(" (Status:")` instead of regular expressions, guaranteeing $O(N)$ linear-time parsing.

### 4. Secret Scrubbing & XML Boundary Neutralization (`ether.core.executor`, `ether.common`)
- Expand `sanitize_subprocess_env()` with prefix filters (`AWS_`, `AZURE_`, `GOOGLE_`, `SSH_`, `DOCKER_`, `NPM_`), suffix filters (`*_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`), and exact names (`DATABASE_URL`, `VAULT_TOKEN`).
- Update `sanitize_untrusted_output()` to match `<(?:/\s*)?untrusted_scan_output\b[^>]*>` (case-insensitive) and escape both opening and closing tags.

### 5. Atomic Permissions & Storage Hardening (`ether.paths`, `ether.graph.store`)
- In `atomic_create_file()`, write to a temporary file with explicit `0o600` permissions and atomically replace via `os.replace`.
- In `GraphStore`, create database directories with `mode=0o700` and pre-create database files with `0o600` before SQLite initialization.

### 6. Deception Heuristics, Tarpit Deadlines & Banner Analytics
- Enforce cumulative monotonic request deadlines in `http_probe`.
- Capture raw service banners in `nmap` and `tools/tcp_probe/`.
- Feed known honeypot banner signatures (`Cowrie`, `Dionaea`, `Kippo`) and timing latency anomalies into `GraphAnalyticsEngine.evaluate_deception()`.

### 7. HTTP Telemetry Enrichment & Schema Classification (`tools/http_probe`, `tools/tls_probe`)
- Add sanitized `body_preview` (first 2 KB) and `redirect_location` to `HttpEndpointFinding`.
- Parse `IP:PORT` targets as `network.service` in `preflight.py` and `tls_probe`.
- Flag metadata open-redirects in `imds_probe`.

### 8. Deterministic Graph Edge Wiring (`ether.graph.store`)
- In `GraphStore.upsert_findings()`, automatically establish hierarchical edges:
  `network.host` -> `network.service` -> `web.endpoint` -> `vulnerability`.

### 9. CLI Universal `--json` Contract & 64-character Node IDs (`ether.cli`)
- Standardize `-j / --json` across all CLI subcommands to emit machine-readable JSON directly to stdout.
- Redirect all progress, status, and diagnostic messages to stderr in JSON mode.
- Output full 64-character SHA-256 node IDs in JSON payloads.

### 10. SDK Ergonomics & Dynamic MCP Metadata (`ether/__init__.py`, `ether.mcp.server`)
- Export `ExecutionSession`, `GraphStore`, `WriteQueue`, `EngagementScope`, `GatePolicy`, `ActionGateway`, `ScopeValidator`, and `BaseFinding` at top-level `ether`.
- Provide default parameterless constructor for `ExecutionSession()`.
- Auto-invoke `_ensure_schema()` on `GraphStore` creation.
- Populate MCP `server_info.version` dynamically from installed package metadata.

## Consequences
- **Positive:**
  - Guaranteed `<10 MB` peak RSS memory delta during intense streaming.
  - Complete elimination of SSRF, DNS rebinding, and flag smuggling bypasses.
  - Machine-readable CLI symmetry with zero table truncation for AI agents.
  - Automatic topological graph wiring for attack paths and blast radius queries.
- **Trade-offs:**
  - Unresolvable domain names are strictly blocked in `SAFE` mode unless `UNRESTRICTED` is explicitly enabled.
  - Subscribers on overloaded queues will lose oldest events to protect engine stability.
