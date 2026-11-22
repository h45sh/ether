# Ether Headless CLI Operations Manual

Welcome to the **Ether Headless CLI Operations Manual**. This guide provides comprehensive operational instructions for driving Ether's reactive execution engine, inspecting tool adapters, managing entity graphs, executing semantic searches, querying agent telemetry deltas, and launching the native MCP server.

---

## 1. Global Command-Line Options

The `ether` binary accepts global options that configure the database, data directories, plugin discovery, logging verbosity, and security policies:

```bash
ether [GLOBAL_OPTIONS] <SUBCOMMAND> [SUBCOMMAND_OPTIONS]
```

| Flag | Long Option | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-h` | `--help` | — | — | Display help and usage summary. |
| — | `--data-dir PATH` | `ETHER_DATA_DIR` | `~/.ether` | Base application directory for logs, scratchpad, and state. |
| — | `--db PATH` | — | `~/.ether/ether.db` | Target SQLite database file. Supports `:memory:` for ephemeral runs. |
| — | `--tools DIR` | — | Bundled `tools/` | Directory path containing pluggable tool adapters. |
| `-j` | `--json` | — | `false` | Output results in machine-readable JSON format. |
| `-v` | `--verbose` | — | `false` | Enable verbose debug logging to stderr. |
| — | `--policy MODE` | — | `safe` | Gate policy mode: `safe` (SSRF/IMDS defense & scope) or `unrestricted`. |
| `-V` | `--version` | — | — | Display Ether version and exit. |

---

## 2. System Diagnostics (`ether doctor`)

Run environmental, database, and toolchain checks to verify system readiness:

```bash
# Human-readable diagnostic report
ether doctor

# Output as machine-readable JSON
ether doctor --json
```

**Checks Performed:**
* Operating system architecture and Python runtime version.
* SQLite engine version and WAL journal capability.
* `sqlite-vec` extension loadability and vector virtual table support.
* Availability and executable paths for all registered security tools (`nmap`, `nuclei`, `ffuf`, etc.).

---

## 3. Tool Adapter Inspection (`ether tool`)

Inspect registered security tools, capabilities, and required arguments:

```bash
# List all registered tool adapters
ether tool list

# List adapters in JSON format
ether tool list --json

# Inspect detailed metadata for a specific tool
ether tool info nmap
ether tool info nuclei --json
```

---

## 4. Supervised Tool Execution (`ether run`)

Execute a security tool scan under Ether's reactive supervisor. Child stdout is normalized streamingly into typed findings and upserted into the session's entity graph:

```bash
# Run a port scan against a target host in the default session
ether run nmap 192.168.1.50

# Run with custom parameters and explicit session binding
ether run nmap 10.0.0.1 --session-id <SESSION_ID> --params '{"raw_flags": "-sV -p 80,443"}'

# Execute under UNRESTRICTED policy (red-team workstation mode)
ether run nmap 10.10.10.20 --policy unrestricted --params '{"raw_flags": "-p-"}'

# Output execution metrics and summary as JSON
ether run nuclei https://example.com --json
```

---

## 5. Session & Workspace Management (`ether session`)

Manage operational boundaries and investigation sessions:

```bash
# List active sessions in the database
ether session list

# Filter sessions by workspace
ether session list --workspace-id <WORKSPACE_ID>

# Output session listing as JSON
ether session list --json

# Create a new investigation session
ether session create "External Perimeter Assessment"

# Create a session under a specific workspace
ether session create "API Fuzzing" --workspace-id <WORKSPACE_ID>
```

---

## 6. Entity Graph Management & Search (`ether graph`)

Query, inspect, prune, export, and search discovered entities in the reactive graph:

### A. Listing Finding Nodes
```bash
# List all active finding nodes in a session
ether graph list-nodes <SESSION_ID>

# Filter by finding schema type
ether graph list-nodes <SESSION_ID> --type network.service
ether graph list-nodes <SESSION_ID> -t vulnerability.found

# Include decayed stale nodes
ether graph list-nodes <SESSION_ID> --include-stale

# Output nodes as JSON with full PIK and attribute data
ether graph list-nodes <SESSION_ID> --json
```

### B. Offline Semantic Similarity Search
Perform natural language k-NN vector search against findings using embedded `sqlite-vec`:

```bash
# Search for web servers or path traversal flaws
ether graph search <SESSION_ID> "Apache HTTP Server path traversal"

# Limit returned findings and enforce minimum similarity score
ether graph search <SESSION_ID> "OpenSSH remote code execution" --limit 5 --min-score 0.3

# Filter vector search by schema type
ether graph search <SESSION_ID> "WordPress CMS" --type web.technology

# Machine-readable JSON output with similarity scores
ether graph search <SESSION_ID> "critical RCE CVE" --json
```

### C. State Pruning (Decayed Nodes)
Permanently remove stale nodes older than a specified retention window:

```bash
# Prune stale nodes older than 7 days (default: 604800 seconds)
ether graph prune <SESSION_ID>

# Prune stale nodes older than 1 hour
ether graph prune <SESSION_ID> --max-age 3600 --json
```

### D. Encrypted Session Export & Import
Export investigation graphs into portable JSON or encrypted archives with Argon2id + AES-256-GCM:

```bash
# Export unencrypted session graph to JSON
ether graph export <SESSION_ID> -o investigation.json

# Export encrypted archive (prompts for passphrase or pass --passphrase)
ether graph export <SESSION_ID> -o session.enc --encrypt --passphrase "StrongPassword123!"

# Import findings into a target database
ether graph import session.enc --passphrase "StrongPassword123!" --session-id <NEW_SESSION_ID>
```

---

## 7. Agent Telemetry Protocol (`ether telemetry`)

The Agent Telemetry Protocol exposes token-budgeted graph snapshots and zero-token diffs designed for autonomous AI agents (Cursor, Claude, Swarms):

### A. Token-Budgeted State Snapshots
Compile a point-in-time snapshot utilizing dynamic programming 0/1 knapsack budgeting to fit findings into a strict LLM token window:

```bash
# Compile default 4000-token state snapshot
ether telemetry snapshot <SESSION_ID>

# Compile snapshot with specific token budget and target focus entity
ether telemetry snapshot <SESSION_ID> --max-tokens 2000 --entity <NODE_ID>

# Supply task objective for automated offline vector RAG finding injection
ether telemetry snapshot <SESSION_ID> --objective "Find exploitable web vulnerabilities on port 80" --json
```

### B. Zero-Token Set-Theoretic Diffs
Query incremental graph deltas ($\Delta = S_{t+1} \setminus S_t$) to eliminate LLM context bloat:

```bash
# Query diff produced by a specific tool execution action
ether telemetry diff <SESSION_ID> --action-id <ACTION_ID>

# Query diff produced since a baseline timestamp (ISO or Unix epoch)
ether telemetry diff <SESSION_ID> --since "2026-11-22T20:00:00Z"

# Output diff as machine-readable JSON
ether telemetry diff <SESSION_ID> --action-id <ACTION_ID> --json
```

---

## 8. Process Execution Logs (`ether logs`)

Inspect append-only session activity feeds, terminal spools, and crash traces:

```bash
# Inspect the most recent 50 action log events for a session
ether logs <SESSION_ID>

# Limit log records returned
ether logs <SESSION_ID> --limit 20

# Filter exclusively for crash events and non-zero exit codes
ether logs <SESSION_ID> --crashes

# Output event log as JSON
ether logs <SESSION_ID> --json
```

---

## 9. Native Model Context Protocol Server (`ether mcp`)

Launch Ether as a native Model Context Protocol (MCP) server over standard I/O (stdio) or Server-Sent Events (SSE) for AI agent integration:

```bash
# Launch stdio MCP server (for Claude Desktop, Cursor, Zed)
ether mcp

# Bind MCP server to a specific persistent session
ether mcp --session-id <SESSION_ID>

# Run MCP server under UNRESTRICTED policy
ether mcp --policy unrestricted

# Launch SSE HTTP daemon for network agent access
ether mcp --transport sse --port 8000
```

**Exposed MCP Tools:**
* `execute_tool`: Supervise and run tools with timeout and output capture.
* `query_graph`: Query typed finding entities and attributes from the graph.
* `inspect_entity`: Fetch detailed attributes, PIK, and incident edges for a node.
* `get_diff`: Retrieve zero-token delta envelope for an action or baseline timestamp.
* `search_findings_semantic`: Natural language vector search via `sqlite-vec`.
* `abort_action`: Terminate active running background scan tasks.
