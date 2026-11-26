---
name: ether-operator
description: High-velocity workflow for operating Ether via MCP or CLI without context bloat.
---

# Ether High-Velocity Operator Workflow

Follow this 3-step loop to minimize LLM round-trips and context tokens:

1. **Discover Lazily (1 call):**
   - **MCP:** `search_tools(query="...", accepts="...", produces="...")`
   - **CLI:** `ether tool search <query> --json`
   - Never dump the full arsenal upfront when you already know the target schema.

2. **Execute Profile-First (1 call):**
   - **MCP:** `execute_tool(tool_name="nmap", target="10.0.0.1", profile="fast")`
   - **CLI:** `ether run nmap 10.0.0.1 --profile fast --json`
   - Use `profile="fast"` / `"standard"` / `"deep"` instead of guessing raw flags; pass `arguments={"flags": [...]}` only for custom overrides.
   - Chain multi-stage workflows with `execute_pipeline(expression="subfinder(example.com) | http_probe | nuclei")`.

3. **Read Compact Telemetry & Ops:**
   - Prefer `get_diff` / `get_telemetry_snapshot` (`ether telemetry diff` / `snapshot --json`) over `include_raw=True`.
   - Use `query_graph(include_edges=True)` or `ether graph tree` when full topology is needed; check `ether status`, `ether ps`, `ether kill <action_id>`, `ether report`, and `ether config show --json`.
