# Ether Concrete Engineering & Code Quality Standards

These standards are mechanically enforced via automated linting, property-based tests, and AST verification.

---

## 1. Zero UI Code Invariant
- **Rule:** Under no circumstances may any file inside `src/ether/` import `textual`, `curses`, or any TUI/GUI presentation library.
- **Enforcement:** Enforced via AST inspection in `tests/unit/test_architecture.py`. Ether is strictly a headless runtime engine.

---

## 2. Process Execution Standards
- **Rule:** Never use `shell=True`, `os.system()`, or string concatenation to build commands.
- **Rule:** Always spawn binaries via argument vectors (`List[str]`) using `asyncio.create_subprocess_exec`.
- **Rule:** Never spawn child processes without passing through `sanitize_subprocess_env()` to strip system and cloud secrets.
- **Rule:** Stream process stdout/stderr directly to disk (`LogSpooler` with 64KB buffering) and maintain byte- and chunk-bounded memory ring buffers (`ByteBoundedRingBuffer`, 2 MB and 5,000 chunks per active job) to cap RAM usage (<10MB per active job).

---

## 3. Database & State Standards
- **Rule:** 100% of SQLite database queries must use parameterized placeholders (`?`). String formatting or interpolation into SQL is strictly forbidden.
- **Rule:** Never open and close connections per query. Use the connection manager via `GraphStore._get_conn()`.
- **Rule:** All SQLite connections must enforce:
  ```sql
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  PRAGMA trusted_schema = OFF;
  ```
- **Rule:** Primary Identity Keys (PIK) must be deterministic SHA-256 hashes of `(schema_type + sorted_pik)`. Upserts must be idempotent.
- **Rule:** Vector embeddings in `vec_findings` must be unit-normalized ($||v||_2 = 1.0$) 384-dimensional vectors synchronized during finding ingestion.

---

## 4. Adapter Authoring Standards
- Adapters in `tools/<name>/` must implement `ToolAdapter`.
- Adapters must be stateless and thread-safe.
- Line parsers must streamingly yield subclasses of `BaseFinding`.
- Every adapter must pass the universal 4-stream fuzzing suite (`Broken ANSI`, `Truncated JSON`, `Null Bytes`, `20,000-Token Buffer`).

---

## 5. Security Policy & Sandbox Standards
- Default policy is `GatePolicy.SAFE`: enforces CIDR scope boundaries and permanently blocks cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`).
- Untrusted tool outputs passed to AI systems must be wrapped in `<untrusted_scan_output>...</untrusted_scan_output>` boundary tags with breakout neutralization (`</untrusted_scan_output>` replaced with `<\/untrusted_scan_output>`).

---

## 6. Forensic Integrity & Audit Standards
- **Rule:** Every executed tool action must generate an append-only `AuditRecord` in the session's audit manifest (`~/.ether/audit/{session_id}.jsonl`).
- **Rule:** Audit records must maintain a continuous SHA-256 cryptographic hash chain linking each action to the preceding block.
- **Rule:** Upon session closure, uncompressed log spools must be compacted into `.log.gz` archives with verified checksums.

---

## 7. Clean Engine Invariant (Zero Backward Compatibility Debt)
- **Rule:** Ether is maintained as a clean, modern substrate. Do not introduce legacy shims, dead compatibility wrappers, or deprecated fallbacks.
- **Rule:** Database schemas initialize atomically via `SCHEMA_DDL` without runtime migration loops.

---

## 8. Code Quality Gates
- **Linter:** `ruff check .` (zero warnings or errors).
- **Formatter:** `ruff format .` (line length: 100).
- **Target Python Version:** `>= 3.11` (specifically tested on `py311`, `py312`, `py313`).
- **Pre-commit Checks:**
  1. `ruff check .`
  2. `pytest -m tier0` (Invariants and property tests in <2 seconds).
  3. `pytest -m fast` (Fast unit tests in <5 seconds).
  4. `pytest -m fuzz` (Universal adapter fuzzing suite).
