# ADR 0018: Pre-Epoch 4 Gate — Forensic Sealing, Audit Trail, Origin Identity & CLI Session Seams

## Status
Accepted (Ready for Implementation)

## Context
Following [ADR 0016](0016-architectural-assurance-zero-trust-and-adapter-redesign.md), [ADR 0017](0017-unified-config-high-velocity-adapters-and-wild-node-convergence.md), and empirical Run 6 blind AWS evaluation ([aws_scenario_report.html](../../reports/run_6/aws/aws_scenario_report.html)), four remaining **Pre-Epoch 4 Gate** items were surfaced and resolved through design review:

1. **Forensic Sealing Trust Anchor (`ether.common.session_sealer`, `ether.graph.store`):** `GraphStore.close_session()` does not pass an external Ed25519 signing key from configuration, and `sessions.status == 'CLOSED'` in SQLite is not cryptographically bound to `seal_receipt.json` on persistent stores.
2. **Identity Migration & Endpoint Path Disambiguation (`ether.graph.store`):** Probing multiple distinct URL paths on the same `(host_ip, port)` (e.g., `/`, `/metrics`, `/ftp`, `/rest/admin/application-configuration`) causes `GraphStore` to match all endpoints on their shared `favicon_hash`, emit false-positive `anchored_identity` migration edges, and mark earlier valid endpoints `stale`.
3. **Unified Forensic Audit Trail Seam (`ether.common.forensic_log`, `ether.core.session`):** `ExecutionSession` action completion does not record entries via `ForensicLogManager.record_action_completion()`, causing `ether session verify-audit` to vacuously return `{"valid": true, "entries": []}` on sessions with completed CLI/MCP tool executions.
4. **Symmetric CLI Session-Binding Interface (`ether.cli.router`, `ether.cli.commands.ops`):** `ether report` only accepts an optional positional `session_id` and rejects `-s` / `--session-id`, breaking symmetry with `ether run`, `ether status`, and `ether ps`.

---

## Decision

### 1. External Signing Key Resolution (`EtherSettings.storage` → `SessionSealer`)
- Add `audit_signing_key_path: Optional[str] = None` to `StorageSettings` in `src/ether/config.py`, supporting `ETHER_AUDIT_SIGNING_KEY` (file path or hex/base64 key material) and `ETHER_STORAGE__AUDIT_SIGNING_KEY_PATH`.
- **Resolution Precedence in `GraphStore.close_session()`:**
  1. Explicit `private_key: Optional[bytes]` argument if supplied.
  2. `EtherSettings.storage.audit_signing_key_path` / `ETHER_AUDIT_SIGNING_KEY` if configured.
  3. Node-local `0o600` Ed25519 keypair under `<data_dir>/keys/audit_signing.key` (skipped for `:memory:` unless `data_dir` is explicitly provided).
- Keep `require_trusted_key: bool = False` opt-in on `SessionSealer.verify_seal()` so zero-config local runs work while strict deployments can enforce pre-provisioned keys.

### 2. Fail-Closed `sessions.status` ↔ `seal_receipt.json` Binding
- On persistent stores (`db_path != ":memory:"`, or when `data_dir` is explicitly provided):
  - `SessionSealer.seal_session()` signs `(session_id, status="CLOSED", manifest_sha256, sealed_at)` in `seal_receipt.json`.
  - `verify_seal()` (and `GraphStore` sealed-session verification) fails closed (`valid=False` / `PermissionError` on mutation) if `sessions.status == 'CLOSED'` has a missing, corrupted, or `session_id`/`status`-mismatched `seal_receipt.json`.
- `:memory:` stores without an explicit `data_dir` remain exempt from disk receipt/key I/O.

### 3. `anchored_identity` Service Origin Boundary (`ether.graph.store`)
- **Seam & Interface:** Keep `GraphStore.upsert_findings_batch()` and `get_anchored_migrations()` signatures unchanged; enforce the origin invariant inside `GraphStore`'s anchor-resolution implementation.
- **Origin Invariant:** Extract canonical service origin `(host_ip, port)` (falling back to `scheme://netloc` when `host_ip` is absent) for anchor-bearing findings:
  - **Same origin (`origin_a == origin_b`):** Do **not** emit an `anchored_identity` migration edge and do **not** mark prior endpoints `stale`—distinct URL paths (`/`, `/metrics`, `/ftp`) on the same host and port remain `confirmed`.
  - **Different origin (`origin_a != origin_b`, i.e., `host_ip` or `port` changed):** Emit `anchored_identity` migration edge and transition the superseded node as before.

### 4. Unified Forensic Audit Trail Seam (`ExecutionSession` → `ForensicLogManager`)
- **Wiring:** At `ExecutionSession` action completion (covering `ether run`, MCP `execute_tool`, and `execute_pipeline`), invoke `ForensicLogManager.record_action_completion(...)` automatically after closing the action's `LogSpooler`.
- **`verify-audit` Semantics:**
  - If a brand-new session has `0` completed actions in `event_log` and `0` spool files, return `valid: true`, `entries: []`, `status: "empty"`.
  - If any completed action exists in `event_log` or any `.log`/`.log.gz` spool file exists without a matching signed entry in the audit manifest, fail with `valid: false` (non-zero CLI exit code).

### 5. Symmetric CLI Session-Binding Seam (`ether.cli.router` / `ether.cli.commands.ops`)
- Introduce a single shared CLI helper (`resolve_session_arg(args, context)`) and bind both optional positional `session_id` and `-s` / `--session-id` on `report`, `status`, and `ps`.
- **Precedence & Conflict Handling:**
  - If both positional `session_id` and `-s`/`--session-id` are passed with **different** values, exit with `EXIT_USAGE_ERROR` and a clear diagnostic.
  - If neither is passed, resolve the active pinned session (`ether session use`) or default session.

---

## Acceptance Criteria
1. **Unit & Security Tests:**
   - `close_session()` uses `ETHER_AUDIT_SIGNING_KEY` when set; deleting or tampering with `seal_receipt.json` on a closed persistent DB causes `verify_seal()` to fail closed.
   - Upserting `/`, `/metrics`, and `/ftp` on `16.179.220.153:80` with identical `favicon_hash` produces `0` `anchored_migrations` and `0` `stale` nodes; upserting `16.179.220.153:8080` or `1.2.3.4:80` with the same `favicon_hash` emits an `anchored_identity` migration.
   - Running `ether run` or `execute_tool` populates `ForensicLogManager`'s manifest so `ether session verify-audit <id> -j` returns `valid: true` with non-empty `entries`.
   - `ether report -s <id>`, `ether report <id>`, `ether status -s <id>`, and `ether ps -s <id>` all resolve identically; conflicting positional + `-s` IDs fail cleanly.
2. **CI Parity Gate:** `.venv/bin/ruff check .`, `.venv/bin/ruff format --check .`, `.venv/bin/mypy src/ether`, and full `.venv/bin/pytest` pass with 0 regressions.
