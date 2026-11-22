# 02: Deterministic Action-Scoped Graph Diffing Engine

**What to build:**
Enhance the telemetry compiler to compute deterministic, action-scoped set-theoretic deltas ($\Delta_{action} = S_{action\_end} \setminus S_{action\_start}$). Enable `GraphTelemetryCompiler.compute_graph_diff` to accept an `action_id: Optional[str] = None` parameter. When queried with an `action_id`, return all nodes and edges attributed to that specific execution action without relying on wall-clock timestamps. Format the output as a canonical `Delta Envelope` isolating `added_nodes`, `updated_nodes`, and `added_edges`.

**Blocked by:** 01: Schema Auto-Migration and Action Attribution

**Status:** completed

- [x] Implement `action_id` filtering in `GraphTelemetryCompiler.compute_graph_diff`
- [x] Retain fallback timestamp-based diffing for baseline timestamps
- [x] Standardize the returned `Delta Envelope` payload structure
- [x] Ensure diff computation reports `tokens_consumed: 0` and total delta count
- [x] Add unit tests in `tests/unit/test_telemetry.py` verifying exact set-theoretic delta accuracy without clock drift
