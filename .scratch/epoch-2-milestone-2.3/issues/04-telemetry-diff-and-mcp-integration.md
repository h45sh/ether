# 04: Telemetry Action Diff Updates & MCP Integration

**What to build:**
Update `GraphTelemetryCompiler.compute_graph_diff()` in `src/ether/graph/telemetry.py` to trigger `reconcile_state_decay()` before computing set-theoretic deltas. Report status transitions in `updated_nodes`, and emit `status_breakdown` (`confirmed`, `flapping`, `stale`) and `anchored_migrations` in the diff telemetry envelope. Update the native MCP server in `src/ether/mcp/server.py`: add `include_stale: bool = False` to `query_graph`, and include `status_breakdown` in `execute_tool` responses. Update CLI in `src/ether/cli/commands/graph.py` to add `--include-stale` and `ether graph prune`. Write unit tests in `tests/unit/test_graph_telemetry.py` and `tests/unit/test_mcp.py`.

**Blocked by:** 02: Deterministic State Decay Engine & Stale Query Filtering, 03: Invariant Identity Anchoring & Cross-IP Migration

**Status:** completed

- [x] Update `GraphTelemetryCompiler.compute_graph_diff()` to reconcile decay and emit `status_breakdown`
- [x] Include status shifts in `updated_nodes` and identity migrations in `anchored_migrations`
- [x] Update MCP `query_graph` tool with `include_stale: bool = False` parameter
- [x] Update CLI `ether graph list-nodes` with `--include-stale` and add `ether graph prune`
- [x] Write unit tests in `tests/unit/test_graph_telemetry.py` and `tests/unit/test_mcp.py`
