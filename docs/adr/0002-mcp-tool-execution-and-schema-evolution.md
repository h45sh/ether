# 0002 MCP Tool Execution Lifecycle and Non-Destructive Schema Evolution

## Context
When autonomous AI agents invoke cybersecurity tools through the Model Context Protocol (MCP), they operate in synchronous turns. Tools can finish in milliseconds (DNS lookup) or run for tens of minutes (port range sweep or web crawling). Furthermore, adding `action_id` and `created_at` to `GraphStore` touches a Tier 1 Frozen Core component (`src/ether/graph/store.py`).

## Decision
1. `execute_tool` executes synchronously by default up to `timeout_seconds` (default 120s). If the timeout is exceeded, the process continues running in the background and returns a running status with an `action_id` to prevent MCP client disconnects.
2. Tool responses prioritize structured set-theoretic diffs ($\Delta$). Any raw output requested by the agent is sanitized for secrets and enclosed in `<untrusted_scan_output tool="...">...<\/untrusted_scan_output>` boundary tags.
3. `GraphStore.initialize()` non-destructively inspects SQLite tables via `PRAGMA table_info` and applies idempotent `ALTER TABLE` migrations for missing `action_id` and `created_at` columns on `nodes` and `edges`, guaranteeing zero breaking changes to existing databases.
4. `ether mcp` is added as a first-class CLI subcommand with `stdio` as the default transport and optional `sse` transport.

## Consequences
- Agents receive immediate structured findings for normal scans without needing manual polling turns.
- Long-running scans do not fail or drop connections; they safely degrade to background tracking.
- Test suites and existing workspace databases remain 100% backward compatible without manual migration scripts.
