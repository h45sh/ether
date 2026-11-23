# ADR 0008: Native MCP Server Surface Expansion for Autonomous Agent Operations

## Status
Accepted

## Context
Ether's Model Context Protocol (MCP) server initially exposed 6 minimal tools (`execute_tool`, `abort_action`, `get_diff`, `query_graph`, `inspect_entity`, `search_findings_semantic`).
While these provided essential execution and set-theoretic diff telemetry, autonomous AI agents remained constrained:
1. **Blind Execution**: Agents could not discover available tools, their categories, execution tiers, or parameter contracts (`list_tools`, `get_tool_info`), forcing prompt hallucination or blind trial-and-error.
2. **Missing Strategic Reasoning**: Ether's internal `GraphAnalyticsEngine` calculated multi-hop BFS attack paths, transitive blast radius, and critical crown jewels, but this intelligence was inaccessible via MCP. Agents had to retrieve raw graph nodes and expend thousands of tokens performing topology analysis manually.
3. **Session Lock-in**: Agents could not manage multi-target engagement lifecycles, list workspaces, or switch active sessions.

## Decision
We expand Ether's Native MCP Server surface in `src/ether/mcp/server.py` to a total of 12 canonical tools:

### 1. Tool Arsenal Self-Discovery
- `list_tools()`: Discovers registered tools, execution tiers (`coroutine` vs `subprocess`), installation status, categories, and descriptions.
- `get_tool_info(tool_name: str)`: Inspects input/output schema contracts, binary discovery status, and parameter rules.

### 2. Graph Intelligence & Strategic Pathfinding
- `get_attack_path(source_id: str, target_id: str, session_id?: str)`: Computes shortest multi-hop attack path using `GraphAnalyticsEngine`.
- `get_blast_radius(compromised_node_id: str, max_depth?: int = 10, session_id?: str)`: Calculates transitive compromise blast radius.
- `get_crown_jewels(session_id?: str)`: Identifies all critical high-value assets (Active Directory DCs, databases, Kerberos, RCE CVEs, credentials) and topological choke points.

### 3. Session & Investigation Lifecycle
- `manage_session(action: 'list' | 'create' | 'info', name?: str, session_id?: str)`: Consolidated high-leverage interface managing multi-session lifecycles and workspace isolation.

## Consequences
- **Positive**: Autonomous agents can introspect the arsenal, execute tools with valid schemas, compute strategic attack paths, and manage investigation workspaces autonomously with zero token waste.
- **Positive**: Preserves John Ousterhout's Deep Module design by leveraging existing internal engines (`GraphAnalyticsEngine`, `ToolRegistry`, `GraphStore`) without introducing shallow wrappers.
- **Trade-off**: Increases total registered MCP tools from 6 to 12, well within standard client tool budgets (<30).
