# 0001 Adopting Official MCP SDK and Action-Scoped Graph Deltas

## Context
Ether's Epoch 2 aims to turn Ether into an autonomous agent telemetry substrate. We need a standardized protocol for autonomous AI agents (Cursor, Claude Desktop, LangGraph) to drive security tools and consume graph state without drowning in raw stdout noise or running into clock-drift and concurrency races.

## Decision
1. We adopt the official Python `mcp` SDK (`mcp>=1.0.0`) for `ether.mcp`, using standard asynchronous stdio transport with optional SSE.
2. We partition Epoch 2 into Milestone 2.1 (Native MCP Server + Deterministic Diffs) and Milestone 2.2 (sqlite-vec RAG + Target Dynamics & Decay).
3. We transition graph diffing from wall-clock timestamp comparisons to action-scoped deltas by tracking `action_id` and `created_at` on SQLite `nodes` and `edges`.
4. We expose 5 canonical high-leverage tools (`execute_tool`, `get_diff`, `query_graph`, `inspect_entity`, `abort_action`) mediated strictly by `ActionGateway`.

## Consequences
- Requires adding `mcp>=1.0.0` to `dependencies` in `pyproject.toml`.
- Requires backward-compatible schema updates in `store.py` to ensure existing databases gain `action_id` and `created_at`.
- Eliminates clock synchronization and concurrency issues when computing graph deltas across concurrent tool executions.
