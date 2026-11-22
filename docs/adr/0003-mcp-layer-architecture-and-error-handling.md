# 0003 Headless MCP Layer Architecture and In-Band Error Recovery

## Context
Integrating the Model Context Protocol (MCP) into Ether must preserve Ether's strict unidirectional layer DAG and headless invariant ([AGENTS.md](file:///home/harsh/Documents/ether/AGENTS.md)). Furthermore, security policy violations (e.g. SSRF metadata blocking) must not crash client MCP sessions.

## Decision
1. `ether.mcp` is established as a top-level headless interface package (`src/ether/mcp/`) parallel to `ether.cli`. Lower architectural layers (`gateway`, `core`, `graph`, `schemas`) are strictly prohibited from importing `ether.mcp`, verified by AST architectural checks.
2. `mcp>=1.0.0` is added to core project `dependencies` in `pyproject.toml`.
3. Security gate rejections (such as targeting cloud metadata under `GatePolicy.SAFE`) return structured in-band tool errors (`isError=True`) with actionable remediation guidance, preventing JSON-RPC disconnects.
4. `action_id` attribution is piped through `ActionGateway` down to `GraphStore.upsert_node` and `GraphStore.add_edge` as an optional parameter, ensuring exact set-theoretic action diff attribution without breaking schema interfaces.

## Consequences
- Preserves the unidirectional layer DAG and headless invariant with automated AST verification.
- Agents receive clear corrective feedback when bumping into security boundaries rather than silent failures or process aborts.
