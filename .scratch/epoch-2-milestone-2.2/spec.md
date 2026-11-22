# Specification: Epoch 2 Milestone 2.2 — Unified Dual-Execution Adapter Seam

**Triage Status:** `ready-for-agent`  
**Governing ADRs:** [ADR 0004](file:///home/harsh/Documents/ether/docs/adr/0004-unified-dual-execution-adapter-seam.md), [ADR 0005](file:///home/harsh/Documents/ether/docs/adr/0005-manifest-tiers-and-ssrf-defense.md)  
**Domain Glossary:** [GLOSSARY.md](file:///home/harsh/Documents/ether/GLOSSARY.md)

---

## Problem Statement

In Epoch 1 and Milestone 2.1, Ether executed security tools exclusively by spawning OS child processes (`create_subprocess_exec`) and parsing line-delimited terminal stdout. While essential for compiled security binaries (`nmap`, `nuclei`, `ffuf`, `sqlmap`), this process model introduces severe architectural and performance bottlenecks:

1. **Subprocess Overhead & Event Loop Starvation:** Executing thousands of lightweight network queries (DNS resolution, HTTP header/title discovery, TLS banner inspection) via OS binaries creates heavy process fork/exec thrashing, pipe context switching, and file descriptor saturation.
2. **Shallow Coupling in the Core:** `ExecutionSession` is tightly coupled to OS process vectors (`List[str]`), while callers (`ActionGateway`, `ether.mcp`, and the CLI) only care about emitting normalized Pydantic findings. Callers should not know whether an adapter runs an OS binary or an in-process async coroutine.
3. **In-Process SSRF Vulnerability:** Native coroutines making outbound network connections (`httpx`) within the engine process can become a conduit for internal SSRF, DNS rebinding, and cloud metadata access (`169.254.169.254`) if not subjected to strict pre-connection validation under `GatePolicy.SAFE`.
4. **Telemetry Inconsistency:** Subprocess tools stream raw terminal output to disk spoolers (`data/logs/{action_id}.log`), enabling forensic replay and `include_raw` in MCP. In-process coroutines lack a standardized wire spooling interface, threatening forensic uniformity.

---

## Solution

Deliver **Milestone 2.2** of the Agent Telemetry Protocol by implementing:

1. **The Unified Execution Seam (`ToolAdapter.execute_action`):**
   A single, deep asynchronous generator interface on `ToolAdapter`:
   ```python
   async def execute_action(
       self, target: str, params: Dict[str, Any], context: ExecutionContext
   ) -> AsyncIterator[BaseFinding]: ...
   ```
2. **Dual-Execution Protocol:**
   - **Tier A (Native Async Coroutines):** Implemented directly within `asyncio` using non-blocking async network libraries (`httpx`, `dns.asyncresolver`). Findings are yielded directly with zero OS process forks.
   - **Tier B (Binary Subprocesses):** Subprocess adapters inherit a base implementation in `ToolAdapter` that coordinates with `context.runner`, spools stdout, parses lines via `parse_line()`, and yields findings.
3. **Manifest Execution Tiers (`manifest.toml`):**
   Add `execution_tier = "coroutine" | "subprocess"` (defaulting to `"subprocess"`). For coroutines, binary discovery checks Python library importability rather than system PATH executables.
4. **Built-in Tier A Probes:**
   - **`dnspython`**: Converted from an external CLI subshell to a pure in-process `dns.asyncresolver` coroutine yielding `dns.record` and `network.host` findings.
   - **`http_probe`**: A new high-throughput native HTTP discovery tool (`httpx.AsyncClient`) extracting response status, headers, HTML title, and TLS metadata, emitting `network.service`, `web.endpoint`, and `web.technology` findings.
5. **SSRF & DNS Rebinding Pre-Connect Defense:**
   Under `GatePolicy.SAFE`, Tier A coroutines resolve destination IPs prior to socket connection and immediately abort with `PolicyViolationError` if the destination maps to cloud metadata (`169.254.169.254`), loopback, or out-of-scope private subnets.
6. **Uniform Wire Spooling (`ExecutionContext.spool_line`):**
   Native coroutines stream wire traces (HTTP request/response lines, DNS query/answer summaries) into the action's `LogSpooler`, ensuring `ether logs` and MCP `include_raw: true` behave identically across all tools.
7. **Unified Task Supervision & Cancellation:**
   `ExecutionSession` wraps all tool runs in an `asyncio.Task`. Calling `abort_action(action_id)` uniformly triggers `task.cancel()` for coroutines and `SIGTERM`/`SIGKILL` for child processes.

---

## User Stories

1. As an autonomous AI agent, I want to invoke `http_probe` on a target domain, so that I can rapidly discover active web services, status codes, and server banners without spawning OS subshells.
2. As an autonomous AI agent, I want to resolve DNS records using native `dnspython`, so that high-volume subdomain enumeration completes in seconds with zero process overhead.
3. As an autonomous AI agent, I want `http_probe` and `dnspython` to return identical structured delta envelopes ($\Delta_{action}$), so that my telemetry processing logic does not change between tool tiers.
4. As an autonomous AI agent, I want to pass `include_raw: true` when executing a Tier A native tool via MCP, so that I receive sanitized wire traces inside `<untrusted_scan_output>` boundary tags.
5. As an autonomous AI agent, I want to call `abort_action` on a running Tier A coroutine, so that runaway or unneeded network probes terminate immediately.
6. As a security operator under `GatePolicy.SAFE`, I want `http_probe` to block attempts to access cloud metadata (`169.254.169.254`) and private IPs even if targeted via DNS rebinding domains, so that lab workstations cannot be compromised.
7. As a security operator under `GatePolicy.UNRESTRICTED`, I want `http_probe` to connect to internal services and non-standard ports without artificial CIDR gates, so that red-team engagements proceed unhindered.
8. As a security operator, I want `ether tool list` and `ether tool info` to display whether each tool is an `OS Binary` or `Native Coroutine`, so that I understand execution characteristics and requirements.
9. As a developer adding a new tool adapter, I want to choose between implementing `build_command() + parse_line()` (for external binaries) or `execute_action()` (for pure-Python coroutines), so that authoring remains straightforward and intuitive.
10. As a developer maintaining Ether, I want `ExecutionSession` and `ActionGateway` to consume a single execution interface, so that callers remain completely decoupled from process mechanics.
11. As a security engineer running batch probes against 1,000 targets, I want Tier A coroutines to bound concurrency to 50 simultaneous connections, so that socket exhaustion and file descriptor errors never occur.
12. As a forensic auditor, I want Tier A coroutines to write raw wire summaries to `data/logs/{action_id}.log`, so that post-mortem audit trails are preserved for all operations.

---

## Implementation Decisions

### 1. `ExecutionContext` Interface
Create `src/ether/core/context.py` (or extend `ether/core/session.py`):
```python
@dataclass
class ExecutionContext:
    action_id: str
    session_id: str
    policy: GatePolicy
    log_spooler: Optional[LogSpooler] = None
    runner: Optional[CommandRunner] = None
    
    def spool_line(self, line: str) -> None:
        """Stream raw wire/text log line to disk spooler and memory ring."""
        if self.log_spooler:
            self.log_spooler.write(f"{line}\n")
```

### 2. `ToolAdapter` Dual-Execution Protocol
In `src/ether/registry/adapter.py`:
```python
class ToolAdapter(ABC):
    name: str = ""
    execution_tier: str = "subprocess"  # "coroutine" | "subprocess"
    
    async def execute_action(
        self, target: str, params: Dict[str, Any], context: ExecutionContext
    ) -> AsyncIterator[BaseFinding]:
        """Unified execution seam.
        
        Default implementation drives Tier B binary subprocesses via
        build_command() and parse_line().
        Tier A adapters override this method directly.
        """
        cmd = self.build_command(target, params)
        # Execute via context.runner, stream to context.spool_line, parse, yield
```

### 3. Manifest Evolution (`manifest.toml`)
In `src/ether/registry/manifest.py`:
Add `execution_tier: str = "subprocess"` to `ToolManifest`.
When `execution_tier == "coroutine"`, `binary` is optional. Discovery checks `importlib.util.find_spec(module_name)`.

### 4. Built-in Tier A Adapters
- **`tools/dnspython/adapter.py`**:
  Convert to `execution_tier = "coroutine"`. Use `dns.asyncresolver.Resolver` to asynchronously query A, AAAA, MX, NS, TXT, SOA, PTR, and AXFR. Yields `DnsRecord` and `NetworkHost`.
- **`tools/http_probe/`**:
  Create `tools/http_probe/manifest.toml` and `tools/http_probe/adapter.py`.
  Uses `httpx.AsyncClient` with `limits=httpx.Limits(max_connections=50, max_keepalive_connections=20)`.
  Extracts status code, headers, `<title>`, server banner, TLS cert info.
  Yields `NetworkService`, `WebEndpoint`, and `WebTechnology`.
  Enforces pre-connect IP check against `GatePolicy.SAFE`.

### 5. `ExecutionSession` Supervised Task Dispatch
In `src/ether/core/session.py`:
- `execute()` invokes `adapter.execute_action(target, params, context)`.
- Wraps execution in an `asyncio.Task` tracked in `_active_tasks[action_id]`.
- `abort_action(action_id)` cancels `task.cancel()` if coroutine, or signals process if subprocess.

---

## Testing Decisions

- **Single Primary Seam:**
  `ActionGateway.execute_action(request)` / `ExecutionSession.execute()`:
  Tests invoke both Tier A (`http_probe`, `dnspython`) and Tier B (`nmap`, `whois`) through the exact same gateway interface and assert normalized findings, delta envelopes, and spooled logs.
- **SSRF Testing:**
  Test `http_probe` under `GatePolicy.SAFE` targeting `169.254.169.254`, `localhost`, and internal IPs; verify `PolicyViolationError` is raised before any connection is made.
- **Concurrency & Timeout Testing:**
  Test bounded concurrency semaphore and cancellation semantics with a slow mock HTTP server.
- **AST Architecture Check:**
  Verify that Tier A adapters adhere to the unidirectional layer DAG and import only normalized schemas and common utilities.
