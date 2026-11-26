# ADR 0017: Unified Configuration, High-Velocity Adapters & Wild-Node Convergence

## Status
Accepted (Implementing)

## Context
Following [ADR 0016](0016-architectural-assurance-zero-trust-and-adapter-redesign.md) (Epoch 3, Section 8), an exhaustive audit of `src/ether/` and all 36 `tools/*/adapter.py` + `manifest.toml` pairs identified three remaining structural friction points:

1. **Fragmented Epoch 3 Configuration:** 6 `ETHER_*` environment variables and dozens of Epoch 3 subsystem knobs (ring buffer limits, `WriteQueue` batching, `SecurityMiddleware` rate limits/CORS/mTLS, `PluginTrustMode`, `PinnedTransport.verify_tls`, `PrivilegeGovernor`, `CryptoEngine`, `TemporalDecayEngine`, `GraphAnalyticsEngine` deception thresholds) are scattered as hardcoded defaults or constructor kwargs with no unified `EtherSettings` model, no `config.toml` support, and no introspection CLI/manual.
2. **LLM & CLI Velocity Bottlenecks:**
   - MCP requires a 3-turn handshake (`list_tools` -> `get_tool_info` -> `execute_tool`) and serializes responses with `indent=2`.
   - `manifest.toml` `[profiles]` (`fast`, `standard`, `deep`) are not executable via `execute_tool` or `ether run --profile`.
   - `ToolRegistry.load_tools()` eagerly imports, AST-checks, and `exec()`s all 36 `adapter.py` modules upfront on every CLI/MCP start.
   - `ToolAdapter.execute_action()` and `SupervisedExecutionService.execute_tool()` maintain redundant 2 MB / list stdout buffers alongside `ByteBoundedRingBuffer` and `LogSpooler`.
   - `build_command()` across 36 adapters diverges on `flags` vs `raw_flags`, macro expansion, and `parse_json_lines()` / `sanitize_output()` adoption.
3. **Disconnected Epoch 3 "Wild Nodes" & Duplicated Helpers:**
   - `CryptoEngine` + `GraphStore._sqlcipher_enabled`, `PrivilegeGovernor`, `NodeAttributeMerger`, `SecurityMiddleware` per-tool RBAC, `PluginLoader(STRICT)`, `DiagnosticEngine` live telemetry, and `ExecutionSession` routing in `execute_pipeline` are unwired or bypassed.
   - Duplicate helpers (`PromptInjectionSandbox` vs `sanitize_untrusted_output`, `zeroize_bytes` vs `wipe_buffer`, `INSTALLATION_HINTS` in 2 places, 6 different `0o600` file writers, `hydrate_node_row` bypassed by 4 modules) and broken stubs (`OnnxVectorEmbeddingEngine` dummy `[[1]]`) fragment the architecture.

Since Ether has no external legacy users, clean-break convergence is preferred over compatibility shims.

---

## Decision

### 1. Unified Configuration Deep Module (`ether.config.EtherSettings`)
- Introduce `EtherSettings` (Pydantic v2 + stdlib `tomllib`, zero new dependencies) in `src/ether/config.py` with precedence:
  `CLI flags > ETHER_* env vars > $ETHER_DATA_DIR/config.toml > EtherSettings defaults`.
- Organize into typed sections: `paths`, `execution`, `gateway`, `mcp`, `graph`, `registry`, `storage`, `logging`, `telemetry`.
- Preserve all 6 existing `ETHER_*` env vars (`ETHER_DATA_DIR`, `ETHER_WORDLISTS_DIR`, `ETHER_MCP_AUTH_TOKEN`, `ETHER_ONNX_MODEL_PATH`, `ETHER_CONTAINER_FALLBACK`, `ETHER_CONTAINER_IMAGE`, `ETHER_DEBUG`) and support `ETHER_<SECTION>__<FIELD>` overrides.
- Expose via `ether config show [--json]` and `ether config path`.

### 2. High-Velocity `ToolAdapter` v2 & Lazy `ToolRegistry`
- **Lazy Adapter Loading:** `ToolRegistry.load_tools()` parses lightweight `manifest.toml` files at startup and defers importing/verifying `adapter.py` until `get_tool()` / `get_adapter()` is called for execution.
- **Profile-First Execution:** Add `profile: Optional[str] = None` to `SupervisedExecutionService.execute_tool`, MCP `execute_tool`, and `ether run --profile`. `profile` expands first (`[]` graceful fallback on coroutine tools without profiles), followed by explicit `flags`.
- **Clean-Break Adapter Normalization:** Standardize on `List[str]` `params["flags"]` + unified macro expansion (`{url}`, `{domain}`, `{target}`, wordlist macros) in `ToolAdapter`; remove legacy `raw_flags` string-parsing branches from all 36 `tools/*/adapter.py`.
- **Zero-Copy Streaming:** Remove the redundant 2 MB `stdout_lines` deque from `ToolAdapter.execute_action()` and `raw_chunks` from `SupervisedExecutionService.execute_tool()`.

### 3. Hybrid MCP + CLI Velocity Interface
- **Lean MCP Discovery:** Replace `list_tools()` with `search_tools(query, accepts, produces, include_profiles=True)` returning compact JSON (`separators=(",", ":")`) across all MCP tools. Keep `get_tool_info` for deep single-tool inspection.
- **Per-Tool RBAC Enforcement:** Wire `SecurityMiddleware` / `OperationType` (`telemetry:read`, `graph:query`, `tool:execute`, `session:mutate`) into `EtherMCPServer` tool dispatch and accept `security_middleware` in `create_mcp_server()`.
- **CLI Parity:** Add `--profile` to `ether run`, `ether tool search`, and `ether config show`.

### 4. Wild-Node Convergence & Deduplication
- Wire `NodeAttributeMerger.merge_node_data` into `GraphStore._raw_upsert_findings_batch` and `hydrate_node_row` into `analytics.py`, `telemetry.py`, `vector_index.py`, `drift/engine.py`.
- Wire `CryptoEngine` on persistent `GraphStore` instances when `settings.graph.encrypt_at_rest` is enabled (disabled by default for `:memory:`).
- Wire `PrivilegeGovernor` into `Executor.run_tool()` when enabled by `EtherSettings.execution`.
- Wire `PluginLoader` trust mode & trusted public keys from `EtherSettings.registry` into `ToolRegistry`.
- Route `SupervisedExecutionService.execute_pipeline()` through `self.exec_sess` (`ExecutionSession`) and propagate `timeout_seconds` into `ActionRequest`.
- Wire `DiagnosticEngine` live metrics (`active_workers`, `queue_depth`, `subprocess_latencies`) to `ExecutionSession` / `WriteQueue`.
- Remove `PromptInjectionSandbox` (keep `sanitize_untrusted_output`), `zeroize_bytes` (keep `wipe_buffer`), and `OnnxVectorEmbeddingEngine`'s dummy `[[1]]` stub; unify `INSTALLATION_HINTS`, `SHELL_METACHAR_RE`, `atomic_create_file`, and `Executor` event loop yield (`0.01s`).

### 5. Auto-Synced Documentation & Agent Skill
- Generate `docs/reference/configuration.md` from `EtherSettings` + CLI parser and `docs/reference/tools-catalog.md` from `tools/*/manifest.toml` via `scripts/generate_docs.py`.
- Add a `tier0` doc-sync test ensuring generated docs never drift from live code/manifests.
- Add a concise `.agents/skills/ether-operator/SKILL.md` teaching agents the 3-step high-velocity workflow (`search_tools` / `ether tool search` -> `execute_tool --profile` / `ether run --profile` -> `get_telemetry_snapshot` / `get_diff`).

## Consequences
- **Positive:** Eliminates cold-start adapter import overhead, removes the 3-turn MCP discovery tax, unifies all Epoch 3 settings into one inspectable schema, wires all disconnected security/storage/pipeline nodes, and guarantees doc-to-code parity.
- **Breaking Changes (Intentional):** Removes `raw_flags` shims from adapters, replaces MCP `list_tools` with `search_tools`, and deletes `PromptInjectionSandbox` / `zeroize_bytes` / dummy ONNX stub.
