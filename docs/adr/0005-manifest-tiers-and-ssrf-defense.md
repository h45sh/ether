# ADR 0005: Manifest Execution Tiers, Wire Spooling, and SSRF Pre-Connect Defense

## Status
Accepted

## Context
ADR 0004 established the Dual-Execution Protocol for `ToolAdapter` (`execute_action()`). To operationalize this protocol across tool discovery, security policy enforcement, and logging:
1. The tool registry and manifests (`manifest.toml`) must declare whether a tool runs as an OS binary or an in-process native async coroutine.
2. Tier A native coroutines must emit raw wire traces into the action log spooler so that `ether logs` and the MCP server's `include_raw: True` remain uniform across all tools.
3. In `GatePolicy.SAFE`, in-process network requests must be strictly protected against DNS rebinding SSRF and cloud metadata bypass.
4. High-volume in-process concurrent requests must be bounded to prevent socket starvation.

## Decision
1. **Manifest Declaration (`manifest.toml`):**
   - Add `execution_tier = "coroutine" | "subprocess"` to `manifest.toml` (default: `"subprocess"`).
   - When `execution_tier = "coroutine"`, `binary` is optional. Tool discovery verifies Python module availability (`httpx`, `dnspython`) rather than looking up PATH binaries via `shutil.which`.
   - Tool inspection (`ether tool list`, `ether tool info`) surfaces the execution tier.
2. **Unified Raw Wire Spooling (`ExecutionContext.spool_line`):**
   - `ExecutionContext` exposes `spool_line(line: str)`.
   - Tier A native coroutines write raw wire details (e.g. HTTP status line, request/response headers, DNS query/response text) to `data/logs/{action_id}.log`.
   - Both Tier A and Tier B produce identical on-disk forensic logs and ring buffer lines.
3. **Defense-in-Depth Pre-Connect SSRF Defense:**
   - Under `GatePolicy.SAFE`, `ActionGateway` validates targets upfront.
   - For native coroutine network tools (`http_probe`), the adapter resolves the destination IP address immediately before connecting. If the resolved IP maps to cloud metadata (`169.254.169.254`, `fd00:ec2::254`), loopback, or private ranges outside the authorized engagement CIDR, the request is blocked and raises `PolicyViolationError`.
4. **Internal Concurrency & Timeout Caps:**
   - Tier A probes enforce a default bounded semaphore of `max_concurrency = 50` per action and strict socket timeouts (5.0s connect, 10.0s read).

## Consequences
- Native coroutines and external binaries integrate seamlessly through identical discovery, logging, and security gates.
- Protects the engine from internal SSRF and DNS rebinding attacks even when running in-process coroutines.
- Prevents file descriptor exhaustion during massive batch scans.
