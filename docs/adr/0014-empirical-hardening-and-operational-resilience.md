# ADR 0014: Empirical Hardening & Operational Resilience (Epoch 3, Section 6)

## Status
Accepted (Design Specification)

## Context
Following the live multi-agent AWS benchmark (`reports/run_1/`) and full design-tree grilling of **Epoch 3, Section 6** ([ROADMAP.md#L251-L309](../../ROADMAP.md#L251-L309)), five operational resilience gaps were identified:

1. **Missing Host Binaries:** Autonomous agents missed client-side SPA routes and hidden parameters when external binaries (`katana`, `arjun`, `sqlmap`, `naabu`) were absent from `$PATH`.
2. **Unprivileged Port Scan Latency:** Without root/raw sockets, Nmap defaulted to `-sT`, inflating scan latency (~26.3s per host), while `tools/stealth_scan/adapter.py` already contained an isolated pure-Python SYN/connect sweep implementation.
3. **Lost Findings on Timeout:** Long-running scanners (`nuclei`, `ffuf`) that hit `timeout_seconds` terminated before `ToolAdapter.execute_action` called `parse_output()`, discarding all partial stdout findings.
4. **Unbounded Log Growth vs. Forensic Integrity:** High-throughput runs produced >26 MB of raw console logs, while `ForensicLogManager` (Tier 1 Frozen Core) relies on uncompressed `.log` SHA-256 checksums in `audit_manifest.jsonl`.
5. **Coarse Static TTL Decay:** A static 3600s TTL in `TemporalDecayEngine` did not adapt to high-churn ephemeral cloud containers restarting on sub-15-minute cycles.

## Decision

### 1. Hermetic Container Fallback (`ether.core.container.ContainerizedToolRunner`)
- **Seam Placement:** Sits behind the existing `CommandRunner` protocol (`ether.core.executor.Executor`), preserving `ExecutionSession`, `PipelineEngine`, and all `ToolAdapter` interfaces unchanged.
- **Eligibility Scope:** Applies **only** to external binary adapters (Tier A / Tier C) when `shutil.which(cmd[0])` returns `None`. Never applies to Tier B in-process Python coroutines or `InternalShellAdapter` (`!` commands).
- **Opt-In & Supply-Chain Hardening:**
  - Disabled by default; enabled via `ETHER_CONTAINER_FALLBACK=1` (or explicit runner configuration) using a pinned image reference (`ETHER_CONTAINER_IMAGE`, never silently pulling `:latest`).
  - Invokes `podman` or `docker` via pure argument vectors (`shell=False`) with `--rm`, `--read-only`, `--cap-drop=ALL`, and **no** host `~/.ether` bind-mount.
- **Preflight Alignment:** When `ETHER_CONTAINER_FALLBACK=1` and a container runtime (`podman`/`docker`) is available, `PreflightVerifier._check_binary()` downgrades `BinaryMissing` to an informational warning instead of blocking execution.

### 2. Ambient Raw Socket Acceleration (`ether.core.raw_net.RawNetworkGovernor`)
- **Deduplication & Extraction:** Extract and generalize the pure-Python async TCP SYN / unprivileged `asyncio.open_connection` sweep engine from `tools/stealth_scan/adapter.py` into `ether.core.raw_net.RawNetworkGovernor`.
- **Small Interface:** `fast_syn_sweep(target: str, ports: Sequence[int], timeout_sec: float = 2.0) -> AsyncIterator[ServiceProbeResult]` plus `has_raw_socket_capability() -> bool`.
- **Integration Scope:** Wire `RawNetworkGovernor` directly into `stealth_scan` and expose it as an explicit opt-in pre-discovery mode rather than silently altering `nmap` or `naabu` CLI flags.

### 3. Resilient Heuristic Stream Recovery (`ether.core.recovery.StreamRecoveryEngine`)
- **Smart Adapter / Simple Core:** `ether.core.recovery` provides pure, format-level salvage primitives (`salvage_json_objects(buffer: bytes) -> list[dict]`, `salvage_ndjson_lines(...)`, `salvage_xml_elements(...)`) without generic `BaseFinding` inference in `core`.
- **Timeout Salvage Hook:** In `ToolAdapter.execute_action` (`src/ether/registry/adapter.py`), catch `TimeoutError` / partial-run termination when `stdout_lines` is non-empty, invoke `await self.parse_output("".join(stdout_lines), target, context=context)`, and yield salvaged findings before terminating. JSON/XML adapters (`nuclei`, `ffuf`, `nmap`, `naabu`) call `StreamRecoveryEngine` inside `parse_output` to recover valid entities from truncated streams.

### 4. Storage Quota & Log Lifecycle (`ether.common.storage.StorageLifecycleManager`)
- **Small Interface:** `enforce_retention_policy(logs_dir: Path, max_disk_mb: int = 1000, max_age_days: int = 30, include_forensic: bool = False) -> StoragePruneReport`.
- **Forensic Chain-of-Custody Protection:** Preserves `ForensicLogManager` (Tier 1 Frozen Core) integrity by skipping any `.log` file referenced in an `audit_manifest.jsonl` during routine compression/pruning unless `include_forensic=True` is explicitly passed.
- **Zero-Dependency Compression & Execution Model:** Uses stdlib `gzip` (with optional `zstd` support if installed) on unchained spool logs (`data/logs/*.log`, rotated `system.log*`) via explicit/triggered lifecycle passes (`ether logs prune` or programmatic calls) rather than an unguarded background daemon.

### 5. Adaptive Volatility Scoring (`ether.graph.decay.TemporalDecayEngine`)
- **Tier 1 Preservation:** Implemented entirely inside `TemporalDecayEngine.reconcile_state_decay` (`src/ether/graph/decay.py`) with zero schema or signature changes to `GraphStore` (Tier 1 Frozen Core).
- **Deterministic Formula:**
  - Compute volatility $V_n \in [0.1, 1.0]$ from `data_json["oscillations"]` (e.g., `min(1.0, 0.1 + 0.2 * oscillations)`) plus an ephemeral boost when `data_json.get("ephemeral")` is set.
  - Scale `effective_ttl = max(300, int(base_ttl * (1.0 - 0.75 * volatility)))`, compressing high-churn cloud targets down to a 300-second floor while leaving stable hosts at `base_ttl`.
  - Persist updated `volatility` in `data_json` only when changed.

## Consequences
- **Positive:**
  - Eliminates missing-binary blind spots without polluting host environments or breaking `CommandRunner` abstraction.
  - Eliminates duplication between `stealth_scan` and `ether.core.raw_net`.
  - Timed-out scans preserve partial intelligence without violating `Smart Adapter / Simple Core`.
  - Bounded log disk usage without breaking `ForensicLogManager` SHA-256 audit chains or modifying Tier 1 `GraphStore`.
- **Trade-offs:**
  - Container fallback requires explicit opt-in (`ETHER_CONTAINER_FALLBACK=1`) and a local OCI runtime (`podman`/`docker`).
  - Manifest-tracked forensic logs remain uncompressed by default unless explicitly archived with `include_forensic=True`.
