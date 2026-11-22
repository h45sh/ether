# 04: Supervised Tool Execution and Prompt Sandboxing

**What to build:**
Implement the execution tools (`execute_tool` and `abort_action`) on the MCP server, mediated strictly by `ActionGateway`. Implement sync-with-fallback execution: await the tool up to `timeout_seconds` (default 120s), returning the completed run with action delta envelope; if the timeout expires, detach to background execution and return a running status with `action_id`. Enforce prompt injection defense by sanitizing secrets and encapsulating any raw scanner output in `<untrusted_scan_output tool="...">` XML boundaries. Return structured `isError=True` responses on policy blocks or validation failures.

**Blocked by:** 03: Native MCP Server Skeleton and Graph Read Tools

**Status:** ready-for-agent

- [ ] Implement `execute_tool` tool with `tool_name`, `target`, `arguments`, `session_id`, `timeout_seconds`, and `include_raw`
- [ ] Connect `execute_tool` to `ActionGateway.execute_action` with `action_id` attribution
- [ ] Implement sync-with-fallback execution timeout logic
- [ ] Enforce prompt injection defense via `sanitize_untrusted_output` for raw logs
- [ ] Implement in-band error formatting (`CallToolResult(isError=True, ...)`) for `SecurityViolation` and gateway errors
- [ ] Implement `abort_action` tool terminating active processes via `ExecutionSession.abort_action`
- [ ] Add unit tests in `tests/unit/test_mcp.py` testing successful execution, timeout fallback, prompt encapsulation, and policy rejection
