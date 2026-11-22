# 03: Native MCP Server Skeleton and Graph Read Tools

**What to build:**
Create the `src/ether/mcp/` package using the official Python `mcp` SDK. Implement an asynchronous stdio server transport with automatic session binding (binding to `--session <id>` or active default session). Implement three read-only MCP tools:
1. `query_graph(session_id: str = None, schema_type: str = None, limit: int = 100)`
2. `inspect_entity(entity_id: str, session_id: str = None)`
3. `get_diff(session_id: str = None, action_id: str = None, baseline_timestamp: str = None)`
Verify end-to-end functionality using an in-memory MCP client channel.

**Blocked by:** 02: Deterministic Action-Scoped Graph Diffing Engine

**Status:** completed

- [x] Create `src/ether/mcp/__init__.py` and `src/ether/mcp/server.py` using `mcp.server.fastmcp` or `mcp.server.Server`
- [x] Implement session binding resolver (CLI option, environment variable, or active default)
- [x] Implement `query_graph` tool returning normalized findings and counts
- [x] Implement `inspect_entity` tool returning detailed PIK, attributes, and relationships
- [x] Implement `get_diff` tool invoking `GraphTelemetryCompiler.compute_graph_diff`
- [x] Add in-memory client integration tests in `tests/unit/test_mcp.py`
