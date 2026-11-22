# ADR 0004: Unified Dual-Execution Adapter Seam (ToolAdapter Protocol)

## Status
Accepted

## Context
In Epoch 1, Ether supervised security tools exclusively by spawning OS child processes (`create_subprocess_exec`) via `ExecutionSession` and reading raw stdout lines into `ToolAdapter.parse_line()`. While ideal for compiled binaries (`nmap`, `nuclei`, `ffuf`), this subprocess model introduces significant kernel fork/exec overhead, pipe context-switching, and process table bloat when executing lightweight network operations (such as resolving 10,000 DNS records or performing fast HTTP title/header discovery across thousands of endpoints).

Ether requires a unified *Deep Module* abstraction where callers (`ExecutionSession`, `ActionGateway`, `ether.mcp`, and the CLI) interact with a single execution entry point, completely oblivious to whether the underlying tool runs as an in-process `asyncio` coroutine or an isolated OS child process.

## Decision
1. **Unified Execution Seam (`execute_action`):**
   We define a single execution entry point on `ToolAdapter`:
   ```python
   async def execute_action(
       self, target: str, params: Dict[str, Any], context: ExecutionContext
   ) -> AsyncIterator[BaseFinding]: ...
   ```
2. **Dual-Execution Protocol:**
   - **Tier A (Native Async Coroutines):** Implemented directly within the adapter as asynchronous generators using pure-Python async libraries (`httpx.AsyncClient`, `dns.asyncresolver`). Findings are yielded directly with zero OS process overhead.
   - **Tier B (Binary Subprocesses):** The default base implementation of `execute_action()` automatically invokes `build_command()`, coordinates with `context.runner` (`create_subprocess_exec`), spools stdout to disk, parses streaming lines via `parse_line()`, and yields normalized findings.
3. **Built-in Tier A Probes:**
   - Modernize `dnspython` to execute as a native in-process `asyncio` coroutine.
   - Introduce `http_probe` as a native in-process coroutine for high-throughput HTTP fingerprinting (status, headers, page title, TLS certificate details).
4. **Unified Lifecycle Supervision:**
   In `ExecutionSession`, every action execution is wrapped in an `asyncio.Task`. Cancellation (`abort_action`) uniformly invokes `task.cancel()` for Tier A coroutines and sends `SIGTERM`/`SIGKILL` to Tier B OS child processes.

## Consequences
- Eliminates kernel fork/exec overhead for high-volume network probes, achieving 10,000+ target scans within <150MB RAM.
- Callers and agent interfaces remain completely decoupled from process mechanics.
- Retains full backward compatibility with all existing Tier B compiled tools (`nmap`, `nuclei`, `ffuf`, `sqlmap`).
