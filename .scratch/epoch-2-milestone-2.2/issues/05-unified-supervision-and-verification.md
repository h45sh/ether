# 05: Unified Task Supervision, Cancellation, and Full Verification

**What to build:**
Unify lifecycle supervision and cancellation across both execution tiers in `ExecutionSession`. In `src/ether/core/session.py`, wrap all action executions in an `asyncio.Task` tracked in `_active_tasks[action_id]`. In `ExecutionSession.abort_action(action_id)`, cancel the task if it is a coroutine, or send `SIGTERM`/`SIGKILL` if it is a subprocess. Verify that `ether.mcp`'s `execute_tool` and `abort_action` handle both Tier A and Tier B tools uniformly. Update AST layer checks in `tests/unit/test_architecture.py` ensuring the new adapters adhere strictly to the unidirectional layer DAG. Run full regression verification (`pytest -m tier0`, `pytest -m fast`, full `pytest`, `ruff check .`).

**Blocked by:** 03: Native dnspython Coroutine Conversion, 04: Native http_probe Adapter with SSRF Pre-Connect Defense

**Status:** ready-for-agent

- [ ] In `ExecutionSession`, wrap execution in `asyncio.Task` and implement unified cancellation in `abort_action()`
- [ ] Add unit tests in `tests/unit/test_execution_session.py` verifying cancellation of both coroutine and subprocess actions
- [ ] Verify `ether.mcp` tool execution and cancellation with native tools in `tests/unit/test_mcp.py`
- [ ] Update AST layer DAG tests in `tests/unit/test_architecture.py` to cover `tools/http_probe`
- [ ] Verify full test suite (`.venv/bin/pytest`) and linter (`.venv/bin/ruff check .`) pass with zero regressions
