# 01: ExecutionContext and ToolAdapter Dual-Execution Protocol Base

**What to build:**
Create `src/ether/core/context.py` defining `ExecutionContext` with `action_id`, `session_id`, `policy`, `log_spooler`, `runner`, and `spool_line(line: str)`. Update `src/ether/registry/adapter.py` to define `execution_tier: str = "subprocess"` and the unified `execute_action(self, target: str, params: Dict[str, Any], context: ExecutionContext) -> AsyncIterator[BaseFinding]` default implementation. Update `ExecutionSession.execute()` in `src/ether/core/session.py` to delegate directly to `adapter.execute_action(target, params, context)`. Ensure all existing 11 Tier B subprocess tools pass existing test suites without regressions.

**Blocked by:** None (can start immediately)

**Status:** completed

- [x] Create `src/ether/core/context.py` with `ExecutionContext` and `spool_line()`
- [x] Add `execution_tier = "subprocess"` and `execute_action()` base implementation to `ToolAdapter` in `src/ether/registry/adapter.py`
- [x] Update `ExecutionSession.execute()` in `src/ether/core/session.py` to delegate to `adapter.execute_action()`
- [x] Verify existing test suite passes (`.venv/bin/pytest tests/unit/test_execution_session.py tests/integration/test_executor_flow.py`)
