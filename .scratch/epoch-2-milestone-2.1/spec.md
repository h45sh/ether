# Specification: Epoch 2 Milestone 2.1 — Agent Telemetry Protocol & Native MCP Server

**Triage Status:** `ready-for-agent`  
**Governing ADRs:** [ADR 0001](file:///home/harsh/Documents/ether/docs/adr/0001-mcp-server-and-action-scoped-diffs.md), [ADR 0002](file:///home/harsh/Documents/ether/docs/adr/0002-mcp-tool-execution-and-schema-evolution.md), [ADR 0003](file:///home/harsh/Documents/ether/docs/adr/0003-mcp-layer-architecture-and-error-handling.md)  
**Domain Glossary:** [docs/reference/glossary.md](file:///home/harsh/Documents/ether/docs/reference/glossary.md)

---

## Problem Statement

Autonomous AI cybersecurity agents (operating within environments like Claude Desktop, Cursor, OpenCode, and LangGraph) face two crippling bottlenecks when executing offensive or defensive security tooling:
1. **Context Window Exhaustion:** Command-line security scanners emit thousands of lines of terminal noise, unstructured text, and repetitive banners. Ingesting raw stdout rapidly consumes context tokens, degrades model reasoning, and incurs heavy API costs.
2. **Lack of Headless Process & Policy Supervision:** Autonomous agents spawning raw subshells have no guardrails: they can execute dangerous commands outside engagement scope, target cloud metadata endpoints (`169.254.169.254`), leak host API keys into target networks via environment variables, or fall victim to prompt injection embedded in target banners.

Currently, Ether has a hardened process supervisor and SQLite entity graph, but lacks a standardized Model Context Protocol (MCP) interface and deterministic action-scoped diff engine. AI agents have no structured way to trigger tool executions, query normalized findings, or receive zero-token graph deltas.

---

## Solution

Deliver **Milestone 2.1** of the Agent Telemetry Protocol by building:
1. **A Native MCP Server (`ether.mcp`):** Exposing five deep, high-leverage tools (`execute_tool`, `get_diff`, `query_graph`, `inspect_entity`, `abort_action`) mediated by `ActionGateway` over standard asynchronous stdio (and optional SSE).
2. **Action-Scoped Deterministic Graph Diffing:** Enhancing `GraphStore` and `GraphTelemetryCompiler` to record `action_id` and `created_at` on nodes and edges, returning exact set-theoretic delta envelopes ($\Delta_{action} = S_{action\_end} \setminus S_{action\_start}$) that eliminate LLM token bloat by up to 98%.
3. **In-Band Prompt-Injection and Secret Defense:** Wrapping raw scan outputs in `<untrusted_scan_output>` boundary tags with closing tag neutralization, stripping secrets from environments, and returning structured error responses with remediation guidance upon policy blocks.
4. **Headless CLI Command (`ether mcp`):** Enabling zero-config agent integration into client configurations.

---

## User Stories

1. As an autonomous AI agent, I want to discover available security tools via MCP, so that I can dynamically select appropriate recon and scanning tools without hardcoding command flags.
2. As an autonomous AI agent, I want to invoke `execute_tool` with a tool name and target, so that the execution runs under strict process supervision and policy controls.
3. As an autonomous AI agent, I want `execute_tool` to await execution synchronously up to a timeout, so that I receive immediate scan results in the current conversation turn.
4. As an autonomous AI agent, I want long-running scans that exceed the timeout to gracefully transition to background supervision and return an `action_id`, so that my MCP client connection is never dropped.
5. As an autonomous AI agent, I want `execute_tool` to return a structured delta envelope of newly discovered nodes and edges, so that I can inspect newly discovered attack surface with zero token waste.
6. As an autonomous AI agent, I want any raw scanner output included in tool responses to be enclosed in `<untrusted_scan_output>` XML boundary tags, so that malicious content in target banners cannot hijack my instructions.
7. As an autonomous AI agent, I want to call `get_diff` with an `action_id`, so that I can retrieve the exact set of graph mutations produced by that specific tool execution.
8. As an autonomous AI agent, I want to call `get_diff` with a timestamp baseline, so that I can see all discoveries made since an earlier point in the engagement.
9. As an autonomous AI agent, I want to call `query_graph` filtered by schema type (e.g. `network.service`), so that I can enumerate specific targets for follow-up testing without reading the full database.
10. As an autonomous AI agent, I want to call `inspect_entity` with an entity ID, so that I can retrieve the full PIK, data payload, parent relationships, and associations of a specific finding.
11. As an autonomous AI agent, I want to call `abort_action` with an active action ID, so that I can terminate runaway or unneeded scan processes immediately.
12. As a security operator configuring Claude Desktop or Cursor, I want to run `ether mcp`, so that my AI assistant automatically gains safe, structured access to Ether's tool arsenal.
13. As a security operator in an educational lab, I want `ether mcp` to enforce `GatePolicy.SAFE` by default, so that AI agents cannot accidentally attack cloud metadata services or out-of-scope networks.
14. As a penetration tester on an authorized red-team engagement, I want to launch `ether mcp --policy unrestricted`, so that my AI agent can assess arbitrary targets and ports without policy restrictions.
15. As a security operator running parallel investigations, I want to specify `--session <id>` on `ether mcp`, so that agent actions and discoveries are strictly isolated to that engagement session.
16. As an AI agent calling a tool with an invalid target, I want to receive a structured `isError=True` response with remediation guidance, so that I can adjust my parameters instead of crashing the MCP connection.
17. As an existing Ether user with existing session databases, I want `GraphStore.initialize()` to automatically upgrade the database schema without data loss, so that my historical sessions remain fully accessible.
18. As a developer maintaining Ether, I want the codebase to enforce the unidirectional layer DAG, so that `ether.mcp` is never imported by lower storage or core execution layers.

---

## Implementation Decisions

- **Package Placement & Layer Invariant:** The MCP server lives in `src/ether/mcp/` as a top-level headless interface package alongside `src/ether/cli/`. Lower layers (`gateway`, `core`, `graph`, `schemas`, `common`) are strictly prohibited from importing `ether.mcp`.
- **Core Dependency:** `mcp>=1.0.0` is added to core `dependencies` in `pyproject.toml`.
- **Primary Seam (`ActionGateway`):** All tool invocations from `ether.mcp` route through `ActionGateway.execute_action`, ensuring universal enforcement of `GatePolicy.SAFE` / `UNRESTRICTED`, target validation, environment secret scrubbing, and log spooling.
- **5 Canonical MCP Tools:**
  - `execute_tool(tool_name: str, target: str, arguments: dict = None, session_id: str = None, timeout_seconds: int = 120, include_raw: bool = False)`
  - `get_diff(session_id: str = None, action_id: str = None, baseline_timestamp: str = None)`
  - `query_graph(session_id: str = None, schema_type: str = None, limit: int = 100)`
  - `inspect_entity(entity_id: str, session_id: str = None)`
  - `abort_action(action_id: str)`
- **Sync-with-Fallback Lifecycle:** In `execute_tool`, wait for the tool execution task with an asyncio timeout (`timeout_seconds`). On timeout, detach the task in background mode and return `{"status": "running", "action_id": action_id, "message": "Execution continuing in background. Use get_diff(action_id=...) to inspect findings."}`.
- **Untrusted Output Defense:** In `execute_tool`, if `include_raw=True`, raw stdout is scrubbed of credentials via `SanitizingLogFormatter` and wrapped in `<untrusted_scan_output tool="...">...<\/untrusted_scan_output>` via `sanitize_untrusted_output`.
- **In-Band Error Recovery:** Gateway and validation errors return `CallToolResult(isError=True, content=[TextContent(text=json.dumps({"error": err_type, "message": str(err), "remediation": advice}))])`.
- **Schema Auto-Migration:** In `GraphStore.initialize()`, inspect `PRAGMA table_info(nodes)` and `PRAGMA table_info(edges)`. If `action_id` or `created_at` are absent, issue `ALTER TABLE nodes ADD COLUMN action_id TEXT`, `ALTER TABLE nodes ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`, and matching statements for `edges`.
- **Action Attribution Plumbing:** `GraphStore.upsert_node` and `GraphStore.add_edge` accept an optional `action_id: Optional[str] = None`. `ActionGateway` passes the active action ID when saving findings.
- **Delta Envelope Schema:** `GraphTelemetryCompiler.compute_graph_diff` returns:
  ```json
  {
    "session_id": "...",
    "action_id": "...",
    "baseline_timestamp": "...",
    "added_nodes": [...],
    "updated_nodes": [...],
    "added_edges": [...],
    "total_delta_count": 0,
    "tokens_consumed": 0
  }
  ```
- **CLI Subcommand:** `ether mcp` registered in `src/ether/cli/router.py` with `--transport {stdio,sse}`, `--port`, `--session`, and `--policy` options.

---

## Testing Decisions

- **Testing Principles:**
  - Test external observable behavior exclusively, not private implementation details.
  - Test at the highest seam possible to maximize test leverage and catch cross-module interaction bugs.
  - Zero network calls and zero file leakage outside isolated test fixtures (`tmp_path` or `:memory:`).
- **Primary Seam for Verification:**
  - **The Headless MCP Interface Seam (`ether.mcp.server`):** Launch the server in-memory via stdio streams or an in-memory client connection, invoking each of the 5 canonical tools and verifying structured output, policy blocks, and delta generation end-to-end.
- **Secondary Seam:**
  - **The Graph Delta Engine Seam (`GraphTelemetryCompiler.compute_graph_diff`):** In-memory unit tests in `tests/unit/test_telemetry.py` verifying that findings stored with `action_id` produce exact set-theoretic deltas without clock dependence.
- **AST Mechanical Gate:**
  - `tests/unit/test_architecture.py`: Extend AST import checks to assert that `ether.mcp` is at the top of the layer DAG and never imported by any module in `ether/gateway/`, `ether/core/`, `ether/graph/`, or `ether/schemas/`.
- **Prior Art:**
  - Existing `tests/unit/test_cli.py` for CLI argument and command routing.
  - Existing `tests/unit/test_gateway.py` for policy enforcement and security blocking.
  - Existing `tests/unit/test_architecture.py` for AST layer DAG enforcement.

---

## Out of Scope

- **Milestone 2.2 Vector RAG (`sqlite-vec`):** Local embedding generation and semantic finding search will be implemented in the subsequent milestone.
- **Milestone 2.2 Target Dynamics & TTL Decay:** Flapping state estimation and confidence decay windows are deferred to Milestone 2.2.
- **Epoch 3 Chained Execution:** Declarative piping of multiple tools (`ether pipeline`) is deferred to Epoch 3.
- **Interactive PTY Sessions:** Terminal emulation for interactive shells (`msfconsole`, `gdb`) is deferred to Epoch 4.

---

## Further Notes

- Adding `mcp>=1.0.0` ensures direct plug-and-play compatibility with Cursor and Claude Desktop, positioning Ether as the first standardized, headless cybersecurity kernel for autonomous agents.
