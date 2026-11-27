# Ether Unified Interfaces & Engineering Standards

This document is the single authoritative reference for **Ether's three headless interfaces**—**MCP**, **CLI**, and **Python SDK**—and the unified configuration, security, and adapter standards they share.

For exhaustive field-by-field settings and tool tables, see the auto-generated references:
* [Configuration & Settings Reference](configuration.md) (`EtherSettings`)
* [Security Tools Catalog](tools-catalog.md) (generated from `tools/*/manifest.toml`)

---

## 1. Interface Matrix: MCP vs. CLI vs. Python SDK

All three interfaces share the same underlying deep modules (`EtherSettings`, `ToolRegistry`, `ActionGateway`, `ExecutionSession`, `SupervisedExecutionService`, and `GraphStore`).

| Capability | MCP (`ether mcp`) | CLI (`ether ...`) | Python SDK (`ether.Ether`) |
| :--- | :--- | :--- | :--- |
| **Lazy Tool Discovery** | `search_tools(query, accepts, produces)` | `ether tool search [query] [--accepts] [--produces]` | `ether.search_tools(query=..., accepts=..., produces=...)` |
| **Tool Inspection** | `get_tool_info(tool_name)` | `ether tool info <name>` | `ether.registry.get_tool_summary(name)` |
| **One-Shot Execution** | `execute_tool(tool, target, profile="fast")` | `ether run <tool> <target> --profile fast --timeout 60` | `await ether.run(tool, target, profile="fast")` |
| **Pipeline Chaining** | `execute_pipeline(expression)` | `ether pipeline run "<expr>"` | `await ether.pipeline(expr)` |
| **Zero-Token Diff** | `get_diff(action_id=...)` | `ether telemetry diff <session_id>` | `await ether.diff(action_id=...)` |
| **Token-Budgeted Snapshot** | `get_telemetry_snapshot(token_budget=4000)` | `ether telemetry snapshot <session_id>` | `await ether.snapshot(token_budget=4000)` |
| **Graph Query** | `query_graph(schema_type=..., include_edges=False)` | `ether graph list-nodes [session_id]` / `ether graph tree` | `await ether.query(...)` / `await ether.graph()` |
| **Session & Ops** | `manage_session`, `abort_action` | `ether session use <id>`, `ether status`, `ether ps`, `ether kill <id>`, `ether report` | `Ether.open(...)` |
| **Config Introspection** | — | `ether config show [--json]` / `path` / `init` | `EtherSettings.load()` |

---

## 2. Unified Configuration Standard (`EtherSettings`)

Every runtime knob across all subsystems is governed by `EtherSettings` (`src/ether/config.py`) with strict precedence:

1. **CLI flags** (`--data-dir`, `--db`, `--tools`, `--policy`, `--config`, `--verbose`, `--json`, `--timeout`)
2. **Environment variables** (`ETHER_<SECTION>__<FIELD>` or legacy `ETHER_*` aliases)
3. **Config file** (`$ETHER_DATA_DIR/config.toml` or `~/.ether/config.toml`)
4. **Built-in defaults**

See [configuration.md](configuration.md) for the complete schema.

---

## 3. High-Velocity Adapter & Registry Contract

1. **Lazy Adapter Loading:** `ToolRegistry.load_tools()` parses only `tools/*/manifest.toml` metadata at startup. `adapter.py` import and `PluginLoader` verification (`tools/bundle_lock.json` for first-party bundled adapters, `.toml.sha256` + Ed25519 `.py.sig` for external plugins in `strict` mode, plus AST checks) happen lazily on first execution.
2. **Profile-First Execution:** `profile` (`fast`, `standard`, `deep`) expands from `manifest.toml` `[profiles]` first, followed by explicit `flags: List[str]`. Coroutine tools without `[profiles]` gracefully resolve `profile="fast"` to `[]`.
3. **Unified Flag & Macro Expansion:** `ToolAdapter.normalize_flags(params)` and `ToolAdapter.expand_flag_macros(...)` standardize `flags: List[str]`, `{url}`, `{domain}`, `{ip}`, `{target}`, and `{wordlist}` substitution across all 36 adapters.
4. **Zero-Copy Streaming:** Raw output streams directly to disk (`LogSpooler`) and `ExecutionSession`'s `ByteBoundedRingBuffer` (2 MiB / 5000 chunks) without redundant adapter buffers.

---

## 4. Security, RBAC & Wire Standards

* **MCP Wire Format:** All MCP tools return compact JSON (`separators=(",", ":")`) to minimize token overhead.
* **MCP Transport RBAC:** When `transport="sse"` is used with `auth_token`, `SecurityMiddleware` enforces HMAC scoped tokens, IP leaky-bucket rate limiting, CORS origin allowlisting, optional mTLS, and per-tool `OperationType` RBAC (`telemetry:read`, `graph:query`, `tool:execute`, `session:mutate`).
* **GatePolicy & Pinned Transport:** `GatePolicy.SAFE` enforces `EngagementScope`, `FlagFirewall`, and `PinnedTransport` (`verify_tls=True`, DNS-pinned TCP handshakes, validated redirects). `GatePolicy.UNRESTRICTED` unlocks raw red-team execution while preserving pure `List[str]` `create_subprocess_exec` isolation.
* **At-Rest Cryptography:** Persistent `GraphStore` databases auto-enable `CryptoEngine` (ChaCha20-Poly1305 field encryption) when `settings.graph.encrypt_at_rest=True` (`:memory:` stores remain unencrypted for fast hermetic tests).

---

## 5. Python SDK Quickstart

```python
import asyncio
from ether import Ether


async def main() -> None:
    async with Ether.open(policy="safe") as ether:
        tools = ether.search_tools(query="nmap", produces="network.service")
        result = await ether.run("nmap", "10.0.0.1", profile="fast")
        diff = await ether.diff(action_id=result["action_id"])
        print(diff)


asyncio.run(main())
```
