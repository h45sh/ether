# ADR 0011: Deep Seam Refactoring, Zero-Legacy Purge, and High-Fidelity Forensic Telemetry Substrate

## Status
Accepted

## Context
Following the architecture review, codebase-design audit, and rigorous grilling of **Section 5, Epoch 3** ([ROADMAP.md#L216-L250](file:///home/harsh/Documents/ether/ROADMAP.md#L216-L250)), several architectural seams in Ether exhibited shallow wrapper characteristics, destructive in-flight text mutations, and legacy baggage that degraded technical fidelity and obstructed sovereign lab operations:

1. **Destructive Output Truncation (`strip_scanner_noise`):**
   `strip_scanner_noise` acted as a shallow text filter in `ether.common` and `PromptInjectionSandbox.clean_scanner_output()`, dropping lines based on arbitrary prefix heuristics and capping tool output to the last 60 lines. This destroyed critical service version banners, SSL handshake telemetry, and CVE correlation evidence.
2. **Operational Mutilation via In-Transit Credential Redaction (`redact_sensitive_artifacts`):**
   `PromptInjectionSandbox.redact_sensitive_artifacts()` blindly regex-replaced discovered passwords, API tokens, and private keys with `[REDACTED_*]` strings during stream ingestion, breaking the core purpose of offensive credential discovery adapters (`hydra`, `netexec`, `sqlmap`).
3. **Bloated Gateway with Static Target Dictionaries (`DEFAULT_TOOL_TARGETS`):**
   `preflight.py` relied on brittle static lookup tables (`DEFAULT_TOOL_TARGETS`, `WEB_TOOLS`) and rigid hardcoded IP bans (blocking `127.0.0.1` and `sudo`), obstructing legitimate container bridge testing, local lab audits, and stealth SYN sweeps.
4. **Paternalistic Core Prompt Rewriting (`PromptNeutralizer`):**
   `ActionGateway.neutralize_prompt()` translated operator instructions (e.g., converting `exploit` $\to$ `verify vulnerability impact`) directly at the execution gateway. In a headless runtime substrate, altering operator intent or autonomous agent arguments distorts technical fidelity and breaks specialized CLI flags.
5. **Bundled Static Wordlists & Package Bloat:**
   Distributing static wordlists (`src/ether/assets/wordlists/common.txt`) inside the core Python package added distribution bloat and created maintenance friction for environments that already host SecLists.
6. **Flat, Unindexed Log Dumping:**
   `ExecutionSession` dumped unindexed raw output files into a flat directory (`~/.ether/logs/<action_id>.log`). Operators and forensic auditors had no mechanism to correlate logs with sessions, targets, or tools without grepping hundreds of opaque UUID files.
7. **Strict Zero-Backward-Compatibility Mandate:**
   Ether is a fresh, modern engine. The project rejects legacy deprecated shims, transitional no-op wrappers, and backwards-compatibility baggage. All legacy code paths identified above are to be purged cleanly.

---

## Decision

### Part 1: Centralized Stream Capture & Complete Purge of `strip_scanner_noise`
We eliminate shallow output truncation and centralize raw stream capture behind `LogSpooler`:
1. **Relocate `LogSpooler` to `ether.common.forensic_log`:**
   Positioning `LogSpooler` at the `common` layer preserves the strict Unidirectional Layer DAG (`ether.core` and `ether.common` can both access spooling primitives without inverted dependencies).
2. **Full-Fidelity Unmutated Spooling:**
   `LogSpooler` maintains 64KB atomic disk buffering, ANSI stripping, and carriage return overwrite normalization, streaming raw unmutated tool output directly to disk.
3. **Complete Purge of `strip_scanner_noise`:**
   Delete `strip_scanner_noise()` from `ether.common` and remove all invocations from `PromptInjectionSandbox`. Zero legacy shims are retained.
4. **Context-Bounded Prompt Sandboxing:**
   `PromptInjectionSandbox.wrap_untrusted_output(raw_text: str, max_chars: Optional[int] = 100_000)` provides head/tail windowing (first 20KB + last 80KB) with explicit boundary tags solely when formatting prompt telemetry for LLM models. The full un-truncated raw stream remains intact on disk via `LogSpooler`.

### Part 2: Lossless Credential Ingestion & Memory-Seam Confidentiality
We decouple credential confidentiality from ingestion and stream processing:
1. **Complete Purge of `redact_sensitive_artifacts`:**
   Remove destructive regex redaction from `PromptInjectionSandbox` and the process stream pipeline. Tool adapters emit raw, intact credentials into typed `CredentialFinding` models.
2. **In-Memory Heap Scrubbing (`SecureBuffer`):**
   Sensitive credential fields are handled using `SecureBuffer` (`ether.common.secure_memory`). When execution jobs finish or sessions close, `wipe_credentials()` overwrites sensitive memory regions in-place with null bytes via `ctypes.memset`.
3. **Database Security via Atomic File DAC:**
   Credentials stored in SQLite attributes JSON rely on atomic file-level discretionary access control (`mode=0o600` for `ether.db`, `mode=0o700` for data directories per AGENTS.md Section 9), avoiding external passphrases that break headless agent autonomy.
4. **Human-Facing CLI Masking (`--unmask`):**
   Terminal presentation commands (`ether graph search`, `ether session export`) mask secret attributes by default (`********`). Operators supply `--unmask` to reveal plaintext credentials. Machine-to-machine interfaces (MCP, Python SDK) return full fidelity by default.

### Part 3: Deep Rules of Engagement Scope Module (`ether.gateway.scope`)
We introduce a deep `ScopeValidator` module at the gateway seam, replacing static dictionaries:
1. **Interface:**
   ```python
   class ScopeVerdict(NamedTuple):
       allowed: bool
       reason: str
       normalized_target: Optional[str]


   class ScopeValidator:
       @classmethod
       def is_in_scope(cls, target: str, scope: EngagementScope) -> ScopeVerdict: ...
   ```
2. **Implementation:**
   - Uses `RadixTrie` from `ether.common.canonicalize` for $O(k)$ CIDR prefix lookups.
   - Evaluates FQDN wildcard globbing and target normalization.
   - Enforces default-deny cloud metadata defense (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`).
   - Under `GatePolicy.SAFE`, out-of-scope targets and cloud metadata are strictly blocked.
   - Under `GatePolicy.UNRESTRICTED`, out-of-scope targets are allowed with an explicit audit warning recorded in the session manifest.
3. **Purge of `DEFAULT_TOOL_TARGETS`:**
   Delete `DEFAULT_TOOL_TARGETS` and static regex sets from `preflight.py`. Preflight delegates target format validation dynamically to `ToolAdapter.target_schemas` and `manifest.toml` contracts.

### Part 4: Complete Decoupling & Purge of `PromptNeutralizer`
We detach defensive prompt framing from core execution:
1. **Purge `ActionGateway.neutralize_prompt()`:**
   Remove the method and any internal prompt transformation from `ActionGateway.execute()`. Technical tool commands and arguments are executed verbatim.
2. **Upstream Seam Relocation:**
   Relocate defensive framing logic to an optional upstream agent skill (`.agents/skills/`) for planning agents that interact with safety-filtered LLM endpoints, keeping the core runtime engine unpolluted.

### Part 5: Externalized Asset Seam & Dynamic Wordlist Resolution (`ether.registry.assets`)
We establish a clean asset resolution seam:
1. **Interface:**
   ```python
   def resolve_wordlist(spec: str) -> Path: ...
   ```
2. **Resolution Hierarchy:**
   - Strips syntax prefixes (e.g. `-w @common.txt` $\to$ `common.txt`, `wordlist:common.txt` $\to$ `common.txt`).
   - Tier 1: Direct absolute or relative filesystem path.
   - Tier 2: `$ETHER_WORDLISTS_DIR/<spec>`.
   - Tier 3: System wordlist paths (`/usr/share/seclists/.../<spec>`, `/usr/share/wordlists/.../<spec>`).
   - Tier 4: Embedded minimal emergency fallback (`ether/assets/wordlists/minimal.txt`, ~50 common endpoints).
   - Tier 5: Raises `AssetNotFoundError` with actionable remediation commands.
3. **Packaging Cleanup:**
   Remove large static dictionary files (`common.txt`) from package distribution assets, bundling only `minimal.txt`.

### Part 6: Forensic-Grade Session Log Architecture & Auditability (`ether.common.forensic_log`)
We replace flat log dumping with a hierarchical, tamper-evident audit subsystem:
1. **Hierarchical Canonical Partitioning:**
   Session logs are partitioned by session ID:
   `~/.ether/logs/sessions/<session_id>/<timestamp>_<tool>_<sanitized_target>_<short_action_id>.log`
2. **Session Audit Manifest (`audit_manifest.jsonl`):**
   An append-only ledger maintained in the session log directory recording:
   ```json
   {
     "index": 0,
     "timestamp": "2026-11-24T18:00:00Z",
     "action_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
     "tool": "nmap",
     "target": "10.0.0.1",
     "exit_code": 0,
     "log_file": "20261124_180000_nmap_10_0_0_1_9b1deb4d.log",
     "log_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "prev_entry_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
     "entry_sha256": "4a5e1e...c9"
   }
   ```
3. **Cryptographic Chain of Custody:**
   Each entry computes `entry_sha256 = SHA256(prev_entry_sha256 + canonical_json_bytes + log_sha256)`. Any retroactive modification, truncation, or deletion of log files or ledger lines invalidates the hash chain.
4. **Automated Lifecycle Compression:**
   Active streams write uncompressed text. When a session is closed (`session.close()`), `ForensicLogManager` transparently compresses completed `.log` files to `.log.gz` and updates manifest metadata.
5. **Verification CLI Surface:**
   Provide `ether session verify-audit <session_id>` to recompute checksums and exit 0 (valid) or 1 (tampered).

---

## Consequences

### Positive
- **High-Fidelity Telemetry:** Zero lines or banners are dropped or sliced in raw scan logs. Complete SSL certificates, version numbers, and HTTP headers are preserved for analysis.
- **Operational Utility:** Credential discovery tools are functional; raw secrets are captured losslessly and protected in memory and at rest.
- **Deep Seams & High Leverage:** Static dictionaries in `preflight.py` are eliminated; new tools require zero gateway code changes.
- **Forensic Integrity:** Red-teams and sovereign labs gain cryptographic, tamper-evident proof of all executed operations and outputs.
- **Clean Codebase:** Zero legacy baggage or deprecated pass-through wrappers.

### Invariants & Governance
- **Strict Layer DAG:** `ether.common.forensic_log` has zero upward dependencies.
- **Atomic Permissions:** Logs and session artifacts are created with mode `0o600` inside `0o700` directories.
- **Tier 0 Compliance:** All changes must pass AST invariant guards (`pytest -m tier0`) in <2s.
