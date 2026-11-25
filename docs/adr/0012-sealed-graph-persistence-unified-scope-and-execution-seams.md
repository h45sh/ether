# ADR 0012: Sealed Graph Persistence, Unified Scope Validation, and Execution Seams

## Status
Accepted

## Context
Following the architecture review and full design-tree grilling across Pass 1 and Pass 2, several hard-to-reverse contract ambiguities and seam leaks were identified across Ether's gateway, execution, and Tier-1 storage layers:
1. **Conflicting Loopback & SSRF Rules (ADR 0005 vs. ADR 0011):** `PreflightVerifier` recommended `127.0.0.1` while `ether.common.ssrf` blocked `127.0.0.0/8` unconditionally and `ScopeValidator` sat unused at runtime.
2. **Silent Non-Zero Exit Masking (ADR 0010 Part 5):** `Executor` only raised on exit code `127`, causing failed tool runs (`1`, `2`) to report `JobStatusEnum.DONE` and `JobStatus` to lack `exit_code` (breaking `Audit Manifest` recording).
3. **Leaked SQLite Handles & Unsealed Mutators (ADR 0007 & ADR 0010):** `GraphStore.connection()` exposed raw write connections, 12+ write paths bypassed `WriteQueueWorker` and `CLOSED` session sealing, and `vec_findings` ran global KNN before `session_id` filtering.

## Decision

1. **Default-Deny Loopback Under `GatePolicy.SAFE` (`ScopeValidator`):**
   - `ScopeValidator` is the single authoritative target, CIDR, metadata, loopback, and pre-connect async DNS seam (with an injectable DNS resolver for hermetic testing).
   - Under `GatePolicy.SAFE`, loopback (`127.0.0.0/8`, `::1/128`) is **blocked by default** unless `EngagementScope(allow_loopback=True)` is explicitly configured; `GatePolicy.UNRESTRICTED` permits loopback/out-of-scope targets with audit warnings.
2. **Non-Zero Exit Code Failure Semantics:**
   - `JobStatus` tracks `exit_code: Optional[int]`. Non-zero exits transition actions to `JobStatusEnum.FAILED` (`ExecutionFailed` / MCP `NON_ZERO_EXIT`) unless the `Tool Adapter` explicitly declares an exit code non-fatal.
3. **Sealed Tier-1 `GraphStore` & Session-Partitioned `vec_findings` (Pass 2):**
   - Remove `GraphStore.connection()` from the public interface after replacing external SQL callers with `GraphStore` methods (`list_all_sessions()`, `upsert_node_beliefs_batch()`, internal `ActionTimelineRepository` access).
   - Route **all** graph mutations through `WriteQueueWorker` inside `BEGIN IMMEDIATE` batches with centralized `CLOSED`-session `Forensic Sealing`, move all pure reads to `_get_read_conn()`, and hydrate `pik`/`data` dictionaries on returned node records.
   - Partition/scope `vec_findings` KNN queries by `session_id` so multi-session databases never truncate intra-session semantic search.
4. **Externalized `Asset Resolver`:**
   - Consolidate wordlist resolution and macro expansion behind `ether.registry.assets` (with injectable search roots) and remove legacy `.txt.gz` bundles from `src/ether/assets/wordlists/`.

## Consequences
- **Positive:** One authoritative policy seam across preflight, gateway, and HTTP adapters; reliable `Audit Manifest` chain-of-custody; contention-free serialized writes with universal `Forensic Sealing`; and isolated per-session `Finding RAG`.
- **Trade-off:** Local lab workflows targeting `127.0.0.1` under `GatePolicy.SAFE` must explicitly opt in via `EngagementScope(allow_loopback=True)` or `--policy unrestricted`, and Pass 2 requires updating existing callers/tests that rely on `store.connection()` or `_get_conn()`.
