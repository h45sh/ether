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
ether mcp --transport sse --port 8000
```

---

## 3. Authoritative MCP Tool Catalog

The Ether MCP server exposes 6 high-leverage tools:

### 1. `execute_tool`
Supervise and execute a security tool scan.
* **Arguments:**
  * `tool_name` (str): Registered tool name (e.g. `"nmap"`, `"nuclei"`, `"ffuf"`, `"http_probe"`).
  * `target` (str): Target domain, IP address, or URL.
  * `arguments` (dict, optional): Custom parameters (e.g. `{"raw_flags": "-sV -p 80,443"}`).
  * `session_id` (str, optional): Target session ID (defaults to active session).
  * `timeout_seconds` (int, default: 60): Execution timeout.
* **Returns:** Structured JSON execution status, discovered findings count, and sanitized terminal preview.

### 2. `query_graph`
Query discovered entities and services from the persistent graph.
* **Arguments:**
  * `session_id` (str, optional): Target session ID.
  * `schema_type` (str, optional): Filter by schema (e.g. `"network.host"`, `"network.service"`, `"vulnerability.found"`).
  * `limit` (int, default: 100): Maximum entities to return.
  * `include_stale` (bool, default: false): Include decayed stale nodes.
* **Returns:** JSON list of matching node entities with PIK and attribute data.

### 3. `inspect_entity`
Inspect deep relational connections and incident edges for a specific finding node.
* **Arguments:**
  * `entity_id` (str): Deterministic SHA-256 node ID.
  * `session_id` (str, optional): Target session ID.
* **Returns:** Entity finding details and all parent/child/association edges.

### 4. `get_diff`
Retrieve the zero-token set-theoretic delta envelope for an action or baseline timestamp.
* **Arguments:**
  * `session_id` (str, optional): Target session ID.
  * `action_id` (str, optional): Filter changes produced by a specific action execution run.
  * `baseline_timestamp` (str, optional): Filter changes produced since an ISO or epoch timestamp.
* **Returns:** Compact JSON diff:
  ```json
  {
    "action_id": "act-9a8b7c",
    "added_nodes": [
      {"schema_type": "network.service", "pik": {"host_ip": "10.0.0.1", "port": 443, "protocol": "tcp"}}
    ],
    "updated_nodes": [],
    "added_edges": [
      {"source_id": "...", "target_id": "...", "relation_type": "parent"}
    ],
    "status_counts": {"confirmed": 4, "flapping": 0, "stale": 0}
  }
  ```

### 5. `search_findings_semantic`
Natural language similarity search over findings using embedded `sqlite-vec` vector memory.
* **Arguments:**
  * `query` (str): Natural language query (e.g. `"Apache HTTP Server path traversal"`, `"WordPress admin endpoint"`).
  * `session_id` (str, optional): Target session ID.
  * `limit` (int, default: 10): Maximum findings to return.
  * `schema_type` (str, optional): Filter by finding schema type.
  * `min_score` (float, default: 0.0): Minimum cosine similarity threshold [0.0, 1.0].
* **Returns:** Top matching finding entities ranked by similarity score.

### 6. `abort_action`
Safely cancel a long-running or stalled background scan task.
* **Arguments:**
  * `action_id` (str): Action UUID to terminate.
  * `session_id` (str, optional): Target session ID.
* **Returns:** Confirmation of process termination (`SIGTERM` $\to$ `SIGKILL`).

---

## 4. Programmatic Agent Loop Example (Python)

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

## 5. Security Invariant: Prompt Injection Defense

All untrusted scan output processed by Ether's MCP server and telemetry engine is sanitized via `sanitize_untrusted_output()`:
1. Wrapped in structural `<untrusted_scan_output>...</untrusted_scan_output>` boundary tags.
2. Breakout sequences (`</untrusted_scan_output>`) are escaped to `<\/untrusted_scan_output>`.
3. Secret tokens, private keys, and passwords are automatically redacted.

---

## 6. Multi-Client Setup Reference

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

## 7. Practical Agent Prompts & Workflows

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

## 8. Troubleshooting & Verification

### Test Using the Official MCP Inspector
You can verify your Ether MCP server locally using the Anthropic MCP Inspector:

```bash
npx @modelcontextprotocol/inspector /absolute/path/to/ether/.venv/bin/ether mcp
```
The inspector web UI will launch at `http://localhost:5173`, allowing you to inspect tool schemas and execute test calls directly.

### Common Issues
* **`command not found: ether`**: Ensure you supply the absolute path to `.venv/bin/ether` in your JSON config, or activate your virtual environment in your shell.
* **Missing external tools (`nmap`, `nuclei`)**: Run `./scripts/install_deps.sh` to install system binaries, or rely on native in-process coroutine adapters (`http_probe`, `dnspython`).

