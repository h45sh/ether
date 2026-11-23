# Repository Anti-Patterns & Prohibited Techniques (Tier 2)

## 1. Security & Process Execution Anti-Patterns
1. **NEVER use `shell=True` or Concatenate Command Strings**:
   - *Failure Mode*: Arbitrary string interpolation invites command injection and breaks on spaces/special characters.
   - *Replacement*: Construct argument vectors (`List[str]`) passed to `asyncio.create_subprocess_exec` in `src/ether/core/executor.py`.
   - *Verification*: `pytest tests/unit/test_engine_executor.py -k test_run_tool_command_args`
2. **NEVER Pass Host Secrets to Child Subprocesses**:
   - *Failure Mode*: Subprocesses inherit `os.environ` by default, leaking API tokens (`CYGUIDE_*`, `OPENAI_*`, `ANTHROPIC_*`, `AWS_*`, `GITHUB_*`, `VAULT_TOKEN`) to untrusted scripts.
   - *Replacement*: Filter environment dictionaries through `sanitize_subprocess_env()` in `src/ether/core/executor.py`.
   - *Verification*: `pytest tests/unit/test_engine_executor.py -k test_sanitize_subprocess_env`
3. **NEVER Trust Untrusted Scanner Output in LLM Prompts or Expose Raw Tokens**:
   - *Failure Mode*: Scanner output can contain prompt injection payloads or leaked bearer tokens that compromise LLM reasoning and data privacy.
   - *Replacement*: Sanitize tokens and private keys with `sanitize_untrusted_output()` and isolate output in `<untrusted_scan_output>` boundary tags (`src/ether/core/sandbox.py`).
   - *Verification*: `pytest tests/unit/test_sandbox.py`
4. **NEVER Weaken SSRF Filters in `ActionGateway` or Allow Arbitrary Non-User Shell Execution**:
   - *Failure Mode*: Bypassing link-local or cloud metadata filters (`169.254.0.0/16`, IMDSv2, octal/hex IP notations) allows host compromise and cloud credential theft.
   - *Replacement*: Strictly validate destinations via `is_blocked_destination()` in `src/ether/gateway/gate.py`.
   - *Verification*: `pytest tests/unit/test_gateway.py -k test_blocked_destinations`

## 2. Headless Architecture & UI Anti-Patterns
1. **NEVER Import Textual, Curses, or Presentation Libraries in `src/ether/`**:
   - *Failure Mode*: Violates strict headless core invariant; breaks downstream consumption by headless daemons and AI agents.
   - *Replacement*: Keep Ether strictly as a headless runtime engine for security tools. All presentation code lives in consumer applications (like CyGuide).
   - *Verification*: `pytest tests/unit/test_architecture.py -k test_no_textual_imports`

## 3. Storage & Engine Anti-Patterns
1. **NEVER Loop Over Single-Row Inserts in SQLite Transactions**:
   - *Failure Mode*: Massive per-transaction disk write overhead ($O(N)$ commit cost).
   - *Replacement*: Prepare parameter batches and use `db.executemany()` or `upsert_findings_batch()`.
2. **NEVER Accumulate Streaming Logs in Unbounded Lists or Strings**:
   - *Failure Mode*: `+=` string concatenation on high-speed stdout streams causes severe memory fragmentation.
   - *Replacement*: Use bounded `collections.deque(maxlen=5000)` and stream logs directly to disk via `LogSpooler`.
3. **NEVER Penetrate Application Private State Across Modules**:
   - *Failure Mode*: Leaking private attributes (e.g. accessing `_conn`, `_sessions`, or internal connection pools across layers) breaks encapsulation and violates the unidirectional layer DAG.
   - *Replacement*: Expose clean public methods on owning classes.

## 4. Packaging & Release Engineering Anti-Patterns
1. **NEVER Use `pip install -e .` in CI Verification**:
   - *Failure Mode*: Editable installs hide missing package assets, uncommitted manifests, and broken entry points.
   - *Replacement*: Build wheel (`uv build`) and install the `.whl` package in an isolated test environment.
2. **NEVER Mutate Documentation in Automated `--check` Release Gates**:
   - *Failure Mode*: Verification scripts mutating files dirty the git working tree in CI preflight.
   - *Replacement*: Ensure `--check` verification modes in `scripts/generate_schema_registry.py` are strictly read-only.
