# Agent Telemetry Protocol & Native MCP Integration Guide

This guide details how autonomous AI agents, LLM reasoning loops, and developer assistants (Cursor, Claude Desktop, custom agent swarms) interface with Ether via the **Agent Telemetry Protocol** and the native **Model Context Protocol (MCP)** server.

---

## 1. Architectural Problem: Context Window Exhaustion

In traditional setups, giving an AI agent bash access to security tools produces catastrophic context window failure:
* A single `nmap -sV` or `nuclei` run can dump **10,000 to 50,000 tokens** of terminal noise.
* Agents lose track of previous findings, hallucinate syntax, and hit LLM context limits within 2–3 turns.
* Security risks: Raw tool stdout can contain adversarial prompt injection payloads from target HTTP headers or TLS certificates.

### Ether's Solution: The Agent Telemetry Protocol
Ether treats security tools as reactive telemetry emitters and presents the agent with two low-token abstractions:
1. **Zero-Token Set-Theoretic Diffs**: After an action runs, Ether computes $\Delta = S_{t+1} \setminus S_t$ and returns only new or updated findings (0 tokens spent on unchanged graph state or raw terminal noise).
2. **Offline Finding RAG & Knapsack Budgeting**: State snapshots are compressed using 0/1 knapsack dynamic programming under a strict token ceiling (e.g. 4000 tokens), dynamically augmented with semantically related findings retrieved via `sqlite-vec`.

---

## 2. Launching the MCP Server

Ether includes a built-in MCP server that communicates over standard I/O (`stdio`) or Server-Sent Events (`sse`):

### A. Local Stdio Transport (Claude Desktop / Cursor)
```bash
# Launch stdio MCP server for active session
ether mcp

# Bind to a specific persistent session
ether mcp --session-id 4f3e2a1b-c8d9-4e5f-a6b7-8c9d0e1f2a3b

# Run under UNRESTRICTED policy (red-team workstation mode)
ether mcp --policy unrestricted
```

#### Claude Desktop Configuration (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ether": {
      "command": "ether",
      "args": ["mcp"]
    }
  }
}
```

*Tip: If installed via `pipx` or if `ether` is not on your global system `$PATH`, configure Claude Desktop with `pipx run`:*
```json
{
  "mcpServers": {
    "ether": {
      "command": "pipx",
      "args": ["run", "ether-core", "mcp"]
    }
  }
}
```

#### Cursor Configuration (`.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "ether": {
      "command": "ether",
      "args": ["mcp"]
    }
  }
}
```

### B. Remote / Docker SSE Transport
```bash
# Launch SSE server on loopback (auth token optional for local dev)
ether mcp --transport sse --port 8000

# Bind to all interfaces with Bearer token authentication (required under SAFE policy)
ether mcp --transport sse --host 0.0.0.0 --port 8000 --auth-token "your-secret-token"

# Or configure via environment variable
export ETHER_MCP_AUTH_TOKEN="your-secret-token"
ether mcp --transport sse --host 0.0.0.0 --port 8000
```

When connecting to an authenticated SSE endpoint, clients must pass the Bearer token in the `Authorization` header:
```http
GET /sse HTTP/1.1
Host: 10.0.0.5:8000
Authorization: Bearer your-secret-token
```

---

## 3. Authoritative MCP Tool Catalog

The Ether MCP server exposes **18 high-leverage tools** organized across 6 core operational domains (alongside server-level `instructions`, `ether://schemas` & `ether://tools/{tool_name}/guidance` resources, and `perimeter_recon` / `vulnerability_triage` prompts):

### Execution & Process Supervision

#### 1. `execute_tool`
Supervise and execute a security tool scan. If execution exceeds `timeout_seconds`, the action automatically falls back to background execution and returns a running status with an `action_id` to prevent client disconnects.
* **Arguments:**
  * `tool_name` (str): Registered tool name (e.g. `"nmap"`, `"nuclei"`, `"ffuf"`, `"http_probe"`).
  * `target` (str): Target domain, IP address, or URL.
  * `profile` (str, optional): Preset flag profile from `manifest.toml` (`"fast"`, `"standard"`, `"deep"`).
  * `arguments` (dict, optional): Custom parameters (e.g. `{"flags": ["-sV", "-p", "80,443"]}`).
  * `session_id` (str, optional): Target session ID (defaults to active session).
  * `timeout_seconds` (int | float, default: 120): Execution timeout before background fallback.
* **Returns:** Structured JSON execution status, discovered findings count, and sanitized terminal preview.
* **Security Policy & Scope:** Enforces the server's active `GatePolicy` (`safe` by default, or `unrestricted`). Under `safe`, cloud metadata endpoints and loopback addresses (`127.0.0.1`, `::1`) are blocked unless `EngagementScope(allow_loopback=True)` or `GatePolicy.UNRESTRICTED` is configured on the server/gateway. Server `server_info.version` is populated dynamically from package metadata.

#### 2. `abort_action`
Safely cancel a running or stalled background scan task (`SIGTERM` $\to$ `SIGKILL`).
* **Arguments:**
  * `action_id` (str): Action UUID to terminate.
  * `session_id` (str, optional): Target session ID.
* **Returns:** JSON confirmation: `{"action_id": "...", "aborted": true}`.

#### 3. `read_action_log`
Read recent spooled execution log lines for an action, sanitized through prompt injection boundary tags.
* **Arguments:**
  * `action_id` (str): Action UUID to inspect.
  * `tail_lines` (int, default: 50): Number of trailing log lines to return.
* **Returns:** JSON object containing the action status and the sanitized log text preview.

---

### Graph Query & Telemetry

#### 4. `query_graph`
Query discovered entities and services from the persistent SQLite graph.
* **Arguments:**
  * `session_id` (str, optional): Target session ID.
  * `schema_type` (str, optional): Filter by schema (e.g. `"network.host"`, `"network.service"`, `"vulnerability.found"`).
  * `limit` (int, default: 100): Maximum entities to return.
  * `include_stale` (bool, default: false): Include decayed stale nodes.
  * `include_edges` (bool, default: false): Also return all graph edges (`edges`, `total_edges`) for the session.
* **Returns:** Compact JSON object of matching node entities (and edges when `include_edges=True`).

#### 5. `inspect_entity`
Inspect deep relational connections and incident edges for a specific finding node.
* **Arguments:**
  * `entity_id` (str): Deterministic SHA-256 node ID.
  * `session_id` (str, optional): Target session ID.
* **Returns:** Entity finding details and all parent/child/association edges.

#### 6. `get_diff`
Retrieve the zero-token set-theoretic delta envelope ($\Delta = S_{t+1} \setminus S_t$) for an action or baseline timestamp.
* **Arguments:**
  * `session_id` (str, optional): Target session ID.
  * `action_id` (str, optional): Filter changes produced by a specific action execution run.
  * `baseline_timestamp` (str, optional): Filter changes produced since an ISO or epoch timestamp.
* **Returns:** Compact JSON diff containing `added_nodes`, `updated_nodes`, `added_edges`, and `status_counts`.

#### 7. `search_findings_semantic`
Natural language similarity search over findings using embedded `sqlite-vec` vector memory.
* **Arguments:**
  * `query` (str): Natural language query (e.g. `"Apache HTTP Server path traversal"`, `"WordPress admin endpoint"`).
  * `session_id` (str, optional): Target session ID.
  * `limit` (int, default: 10): Maximum findings to return.
  * `schema_type` (str, optional): Filter by finding schema type.
  * `min_score` (float, default: 0.0): Minimum cosine similarity threshold [0.0, 1.0].
* **Returns:** Top matching finding entities ranked by similarity score.

---

### Strategic Graph Intelligence

#### 8. `get_attack_path`
Compute the shortest directed multi-hop attack path connecting two entity IDs using `GraphAnalyticsEngine` BFS traversal.
* **Arguments:**
  * `source_id` (str): Origin entity ID (e.g., initial compromised host).
  * `target_id` (str): Destination entity ID (e.g., database or crown jewel service).
  * `session_id` (str, optional): Target session ID.
* **Returns:** JSON object containing `found: bool` and the ordered list of graph nodes forming the shortest path.

#### 9. `get_blast_radius`
Calculate the transitive compromise blast radius (all downstream reachable nodes) from a compromised entity.
* **Arguments:**
  * `compromised_node_id` (str): Root compromised entity ID.
  * `max_depth` (int, default: 10): Maximum hops to traverse.
  * `session_id` (str, optional): Target session ID.
* **Returns:** JSON object containing `total_affected` count and sorted list of `affected_entity_ids`.

#### 10. `get_crown_jewels`
Identify critical high-value assets (Domain Controllers, databases, Kerberos, RCE vulnerabilities, credentials) and topological choke points via betweenness centrality.
* **Arguments:**
  * `session_id` (str, optional): Target session ID.
* **Returns:** JSON object containing `crown_jewels` list, top `choke_points` ranked by betweenness centrality score, and `total_critical` count.

---

### Arsenal Self-Discovery

#### 11. `search_tools`
Lazily search registered security tools by keyword, accepted schema, or produced schema without dumping the entire arsenal into context.
* **Arguments:**
  * `query` (str, optional): Keyword filter across tool name, summary, description, and category.
  * `accepts` (str, optional): Filter by input finding schema (e.g., `"network.host"`).
  * `produces` (str, optional): Filter by output finding schema (e.g., `"network.service"`).
  * `include_profiles` (bool, default: True): Include executable `[profiles]` presets.
* **Returns:** Compact JSON object `{"total": ..., "tools": [...]}` with `name`, `tier`, `installed`, `accepts`, `produces`, and `profiles`.

#### 12. `get_tool_info`
Get detailed manifest specifications, accepted input formats, emitted finding schemas, and binary discovery paths for a registered tool.
* **Arguments:**
  * `tool_name` (str): Registered tool name (e.g., `"nmap"`, `"http_probe"`, `"nuclei"`).
* **Returns:** Detailed JSON metadata with `input_accepts`, `output_emits`, `execution_tier`, and `binary_path`.

---

### Session & Workspace Management

#### 13. `manage_session`
Unified interface to create, list, or inspect investigation workspaces and sessions.
* **Arguments:**
  * `action` (str): Action to perform (`"list"`, `"create"`, or `"info"`).
  * `name` (str, optional): Session name (when `action="create"`).
  * `session_id` (str, optional): Target session ID (when `action="info"`).
* **Returns:** JSON status, session IDs, and active node counts.

---

### Active Defense & Deception Intelligence

#### 14. `get_deception_report`
Evaluate and retrieve the deception, honeypot, and tarpit report for a session. Identifies active honeypots, delay-tarpits, and low-confidence findings using a 3-factor Bayesian belief engine over port entropy sprawl and banner signatures.
* **Arguments:**
  * `session_id` (str, optional): Target session ID (defaults to active session).
* **Returns:** JSON payload listing `flagged_honeypots`, `active_tarpits`, and `low_confidence_findings`.

---

### Architectural Compliance & Drift Auditing

#### 15. `audit_drift`
Audit an observed session entity graph against an architectural baseline specification (file path or inline JSON string). Calculates normalized Jaccard topological distance $D_{topo} \in [0.0, 1.0]$ and identifies unexpected rogue services or missing required nodes.
* **Arguments:**
  * `baseline` (str): Baseline specification file path or JSON string.
  * `session_id` (str, optional): Target session ID (defaults to active session).
  * `mode` (str, default: `"topology"`): Audit mode (`"topology"` or `"strict"`).
  * `record_findings` (bool, default: `false`): Whether to record `audit.drift` findings into the session graph.
* **Returns:** Structured JSON `DriftReport` with `drift_score`, `mode`, `summary`, and detailed `discrepancies`.

---

## 4. High-Fidelity Execution Error Diagnostics & Autonomous Self-Healing

When tools fail during execution (e.g., host unreachable, binary missing, or command timeout), traditional MCP implementations crash the JSON-RPC channel or return opaque empty findings.

Ether surfaces granular execution telemetry payloads with a standardized `ExecutionErrorCategory` taxonomy without disconnecting the client session:

```json
{
  "is_error": true,
  "error_category": "TARGET_UNREACHABLE",
  "exit_code": 1,
  "stderr_snippet": "Connection refused by remote host 10.254.254.1:80",
  "error": "ConnectionRefusedError",
  "message": "Connection refused by remote host 10.254.254.1:80",
  "remediation": "Verify target host routing and port accessibility."
}
```

### Standardized Error Taxonomy (`ExecutionErrorCategory`):
| Category | Exit Code | Diagnostic Trigger | Agent Self-Healing Action |
| :--- | :--- | :--- | :--- |
| `TARGET_UNREACHABLE` | `1` | Connection refused, host unreachable, no route to host, DNS lookup failure. | Verify target routing, switch to ping/ARP probe, or update target address. |
| `COMMAND_TIMEOUT` | `124` | Execution deadline exceeded configured `timeout_seconds`. | Increase `timeout_seconds` or narrow scan scope (e.g., specific ports instead of `-p-`). |
| `BINARY_MISSING` | `127` | Tool is unregistered or binary executable not found on host `$PATH`. | Fall back to an in-process Tier A coroutine tool (e.g. `http_probe`, `dnspython`). |
| `SCOPE_BLOCKED` | `1` | Preflight gate rejected execution under active `GatePolicy` (SSRF/IMDS). | Refine target scope or switch to `GatePolicy.UNRESTRICTED` if authorized. |
| `NON_ZERO_EXIT` | `1+` | General tool execution failure or abnormal process exit. | Inspect `stderr_snippet` and adjust custom `arguments` flags. |

---

## 4b. Additional MCP Tools, Resources & Workflow Prompts

* **`get_telemetry_snapshot(session_id, token_budget, task_objective, selected_entity_id)`**: Compiles a 0/1 knapsack token-budgeted state snapshot with optional vector RAG objective boosting.
* **`execute_pipeline(expression, session_id)`**: Executes a chained tool pipeline DAG (e.g., `"subfinder(target=example.com) | dnspython | http_probe"`) gated by `ActionGateway` preflight checks.
* **`verify_session_audit(session_id)`**: Verifies the cryptographic SHA-256 chain of custody and log file hashes for a session.
* **MCP Resources**: `ether://schemas` (lists all 25 normalized finding schemas and PIK fields) and `ether://tools/{tool_name}/guidance` (dynamic target scope and safety guidance).
* **MCP Prompts**: `perimeter_recon(target)` and `vulnerability_triage(session_id)` workflow templates.
* **Server Instructions**: Sent automatically during MCP handshake summarizing active `GatePolicy`, token-efficiency rules, and `<untrusted_scan_output>` boundaries.
* **Flag Flexibility**: `execute_tool` accepts both `arguments["flags"]` and `arguments["raw_flags"]`, and `read_action_log` transparently decompresses `.log.gz` archives for closed sessions.

---

## 5. Programmatic Agent Loop Example (Python)

Agents can query snapshots and stream deltas directly using the Python SDK:

```python
import asyncio
from ether import GraphStore
from ether.graph.telemetry import GraphTelemetryCompiler


async def agent_reasoning_step(store: GraphStore, session_id: str, current_objective: str):
    compiler = GraphTelemetryCompiler(store, session_id)

    # 1. Compile 4000-token budgeted snapshot with objective-directed RAG
    snapshot = await compiler.compile_telemetry_snapshot(
        max_tokens=4000,
        objective=current_objective,
    )
    print(f"Loaded {len(snapshot['budgeted_findings'])} budgeted findings.")
    print(f"RAG retrieved {len(snapshot['rag_findings'])} contextually relevant findings.")

    # 2. After tool execution, query action-scoped delta (zero-token diff)
    diff = await compiler.compute_graph_diff(action_id="act-12345")
    print(f"Delta: +{len(diff['added_nodes'])} nodes, ~{len(diff['updated_nodes'])} updated.")


if __name__ == "__main__":
    store = GraphStore("~/.ether/ether.db")
    asyncio.run(
        agent_reasoning_step(store, "session-abc", "Find remote code execution on web ports")
    )
```

---

## 6. Security Invariant: Prompt Injection Defense

All untrusted scan output processed by Ether's MCP server and telemetry engine is sanitized via `sanitize_untrusted_output()`:
1. Wrapped in structural `<untrusted_scan_output>...</untrusted_scan_output>` boundary tags.
2. Breakout sequences (`</untrusted_scan_output>`) are escaped to `<\/untrusted_scan_output>`.
3. Secret tokens, private keys, and passwords are automatically redacted.

---

## 7. Multi-Client Setup Reference

### A. Claude Desktop
Add to `~/.config/Claude/claude_desktop_config.json` (Linux) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "ether": {
      "command": "/absolute/path/to/ether/.venv/bin/ether",
      "args": ["mcp"],
      "env": {
        "ETHER_DATA_DIR": "/home/user/.ether"
      }
    }
  }
}
```

### B. Cursor IDE
Create or edit `.cursor/mcp.json` in your workspace root:

```json
{
  "mcpServers": {
    "ether": {
      "command": "/absolute/path/to/ether/.venv/bin/ether",
      "args": ["mcp"]
    }
  }
}
```

### C. Containerized Agent (Docker)
When running your agent harness in a container, expose Ether over Server-Sent Events (SSE):

```bash
# In Ether container
docker run -d --name ether-mcp -p 8000:8000 -v ~/.ether:/root/.ether ether:latest mcp --transport sse --port 8000
```

Configure your agent client with the SSE URL: `http://localhost:8000/sse`.

---

## 8. Practical Agent Prompts & Workflows

Once connected to Ether via MCP, give your agent natural language objectives:

### Scenario 1: Autonomous Web Reconnaissance
> *"Connect to Ether and perform initial reconnaissance against target domain scanme.nmap.org. First execute http_probe, check the graph for endpoints, and then search for open technologies."*
- **Agent Action Flow:**
  1. `execute_tool(tool_name="http_probe", target="https://scanme.nmap.org")`
  2. `get_diff(action_id=...)` -> Agent receives zero-token delta of new endpoints and technologies.
  3. `search_findings_semantic(query="web servers and API endpoints")` -> Agent pinpoints relevant services.

### Scenario 2: Targeted Vulnerability Verification
> *"Inspect the current engagement session for any hosts running Apache or OpenSSH. If discovered, run nuclei with web-cve tags and report newly confirmed vulnerability nodes."*
- **Agent Action Flow:**
  1. `query_graph(schema_type="network.service")` -> Discovers port 80/443.
  2. `execute_tool(tool_name="nuclei", target="https://10.0.0.1", arguments={"raw_flags": "-t cves/"})`
  3. `inspect_entity(entity_id=...)` -> Deep inspection of vulnerability nodes and incident relations.

---

## 9. Troubleshooting & Verification

### Test Using the Official MCP Inspector
You can verify your Ether MCP server locally using the Anthropic MCP Inspector:

```bash
npx @modelcontextprotocol/inspector /absolute/path/to/ether/.venv/bin/ether mcp
```
The inspector web UI will launch at `http://localhost:5173`, allowing you to inspect tool schemas and execute test calls directly.

### Common Issues
* **`command not found: ether`**: Ensure you supply the absolute path to `.venv/bin/ether` in your JSON config, or activate your virtual environment in your shell.
* **Missing external tools (`nmap`, `nuclei`)**: Run `./scripts/install_deps.sh` to install system binaries, or rely on native in-process coroutine adapters (`http_probe`, `dnspython`).

