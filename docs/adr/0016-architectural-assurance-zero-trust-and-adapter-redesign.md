# ADR 0016: Architectural Assurance, Zero-Trust Hardening, Supply-Chain Integrity & Adapter/Manifest Redesign (Epoch 3, Section 8)

## Status
Accepted (Design Specification)

## Context
Following Epoch 3, Section 7 ([ADR 0015](0015-autonomous-agent-usability-security-and-memory-hardening.md)), architectural review of **Epoch 3, Section 8** ([ROADMAP.md:361-506](../../ROADMAP.md#L361-L506)) and the engine-to-tool interface identified 10 structural gaps across execution security, storage integrity, transport safety, and adapter ergonomics:

1. **Legacy CyGuide Relics & Suboptimal Engine ↔ Tool Seam:** `src/ether/registry/manifest.py` and all 38 `tools/*/manifest.toml` files still carry CyGuide curriculum schemas (`[modes]` `learning`/`power`, `learning.flags`, `power.suggests`, and verbose `[[learning.recipes]]` tutorial essays with `difficulty`/`packet_wire_summary`). Meanwhile, `ToolAdapter.execute_action()` buffers up to 2 MB of stdout solely for timeout fallback, lacks a declarative structured-output preference, and provides no machine-readable `[flags]` or `[execution]` contract.
2. **Missing Per-Tool Flag Allowlist Firewall:** `ActionGateway` and `PreflightVerifier` validate target strings and shell metacharacters, but do not validate CLI flags against per-tool manifest allowlists, leaving room for dangerous flag injection (`-oG`, `--script`, `--proxy`, `-iL`, `--config`) under `GatePolicy.SAFE`.
3. **Single-Token MCP SSE Authentication:** `EtherMCPServer` wraps `sse_app()` with a basic `BearerTokenAuthMiddleware` doing string equality on a single static token, with no HMAC scoped tokens, brute-force rate limiting, CORS origin policy, mTLS support, or RBAC segregation between read-only and destructive verbs.
4. **Unverified Dynamic Adapter Loading:** `ToolRegistry._load_adapter()` imports Python modules via `importlib.util.spec_from_file_location` without Ed25519 signature verification, SHA-256 manifest hashing, AST static safety checks, or namespace isolation.
5. **Plaintext Credential Persistence at Rest:** `GraphStore` stores `CredentialFound` secrets and `event_log` payloads in plaintext SQLite, protected only by filesystem permissions (`0o700`/`0o600`), without field-level or page-level encryption or memory zeroization.
6. **Offset-Sliced WriteQueue Coalescing & Unserialized Migrations:** `WriteQueueWorker._process_write_batch()` slices coalesced batch results by input offset (`all_nids[s:e]`), risking misattribution when findings deduplicate, while `export_session()` and `import_session()` bypass the serialized write queue.
7. **Non-Atomic Session Closure & Unsigned Audit Manifests:** `GraphStore.close_session()` compresses logs before updating SQLite status without a two-phase recovery journal, and `ForensicLogManager` hash chains lack asymmetric Ed25519 signatures.
8. **DNS Rebinding TOCTOU & Disabled TLS Verification:** `ScopeValidator.check_destination()` resolves DNS pre-connect without pinning the validated IP to the TCP socket, and `http_probe` / `ffuf` default to `ssl.CERT_NONE` / `check_hostname = False`.
9. **Ambient Container Capabilities:** `Dockerfile` sets `cap_net_raw,cap_net_admin+eip /usr/bin/nmap`, and the Python supervisor process does not drop capabilities or set `PR_SET_NO_NEW_PRIVS`.
10. **Supply-Chain & Benchmark Reproducibility Gaps:** Release workflows lack CycloneDX SBOM generation and Cosign container signing, CI lacks `uv lock --check`, and adversarial boundary tests are not consolidated into a dedicated security suite.

Since Ether has no legacy external-user backward-compatibility burden, clean-break interface upgrades are preferred over compatibility shims.

---

## Decision

### 1. Manifest & `ToolAdapter` Redesign (`ether.registry.manifest`, `ether.registry.adapter`, `tools/*/manifest.toml`)
Purge all CyGuide relics and elevate `manifest.toml` + `ToolAdapter` into an optimal, non-bottleneck engine ↔ tool contract:

- **Purge CyGuide Schemas:** Remove `LearningConfig`, `PowerConfig`, `Recipe`, `RecipeTheory`, `[modes]` (`learning`/`power`), `learning.flags`, `power.suggests`, and `[[learning.recipes]]` from `Manifest` and all 38 `tools/*/manifest.toml` files, plus TUI comments in `adapter.py`.
- **Ether-Native Manifest Sections:**
  - `[flags]`: `allowed: List[str]`, `blocked: List[str]`, `value_types: Dict[str, str]`, `compound_delimiters: List[str]` — single source of truth for `FlagFirewall`.
  - `[execution]`: `tier: Literal["coroutine", "subprocess"]`, `output_format: Literal["ndjson", "json", "xml", "text", "coroutine"]`, `supports_streaming_parse: bool`, `default_timeout_sec: float`.
  - `[profiles]` *(optional, max 1–3 entries)*: concise, machine-usable preset flag vectors (e.g. `fast`, `standard`, `deep` → `List[str]`), zero educational prose. Update `mcp/server.py`, `preflight.py`, and `cli/commands/tool.py` to expose `profiles` instead of `learning.recipes`.
- **Result-Amplifying `ToolAdapter` Seam:**
  - Prefer machine-readable output flags (`-oX -`, `-jsonl`, `-json`) automatically when the caller does not override output format.
  - Stream parsed findings incrementally mid-scan directly to `WriteQueue` / `GraphAnalyticsEngine`, eliminating redundant timeout-only stdout buffering for streaming adapters.
  - Expose `ToolCapabilities` (`accepts`, `produces`, `amplifies_to`) derived from `[input]`/`[output]` so `execute_pipeline` and autonomous agents chain findings (`network.service` → `http_probe` / `tls_probe` / `nuclei`) deterministically.

### 2. Subprocess Argument Allowlisting & Flag Injection Firewall (`ether.gateway.flags`)
```python
class FlagFirewall:
    def validate_arguments(
        self, tool_name: str, args: Sequence[str], policy: GatePolicy
    ) -> Sequence[str]: ...
```
- **Under `GatePolicy.SAFE`:** Derives strict AST allowlists/blocklists directly from each tool's `[flags]` manifest contract (zero hardcoded per-tool rules). Disassembles compound arguments (joined `-uhttp://...`, colon-delimited `--resolve=h:p:ip`, comma-delimited `--targets=a,b`), blocks forbidden proxy/script/output-redirect flags, and strips shell metacharacters (`|`, `;`, `&`, `$`, `` ` ``, `\n`).
- **Under `GatePolicy.UNRESTRICTED`:** Preserves full-spectrum red-team flag flexibility while still neutralizing raw shell-injection metacharacters and enforcing pure `List[str]` vector execution via `create_subprocess_exec`.

### 3. Enterprise MCP Gate & Scoped Transport Authentication (`ether.mcp.security`)
```python
class SecurityMiddleware:
    async def authenticate_request(
        self,
        headers: Mapping[str, str],
        client_cert: Optional[bytes],
        operation: OperationType,
    ) -> AuthContext: ...
```
- **Clean-Break Replacement:** Remove `BearerTokenAuthMiddleware` in `src/ether/mcp/server.py`.
- **HTTP / SSE (and `streamable-http` if supported by `mcp` SDK):** Enforce constant-time HMAC-signed scoped tokens (`telemetry:read`, `graph:query`, `tool:execute`, `session:mutate`) with sliding-window rotation/grace periods, IP leaky-bucket rate limiting, strict CORS origin allowlisting, optional mTLS client-cert verification, and structured request audit logging.
- **`stdio` Transport:** Runs with an implicit local-operator `AuthContext` (configurable scope ceiling).

### 4. Cryptographic Plugin Attestation & Sandboxed Loader (`ether.registry.loader`)
```python
class PluginLoader:
    def load_verified_adapter(
        self, adapter_path: Path, manifest_path: Path
    ) -> ToolAdapter: ...
```
- **Pure-Python Defense-in-Depth (No Wasm Runtime):** Uses `cryptography` (already in `pyproject.toml`) for Ed25519 signature verification against trusted keys and SHA-256 manifest hash verification.
- **AST Static Gate & Namespace Isolation:** Parses `adapter.py` AST to reject unauthorized `eval`, `exec`, raw `socket`, or `subprocess` calls before loading into an isolated module namespace.
- **Trust Modes:** Configurable `strict` (production/CI) vs `dev` (unsigned local adapter development).

### 5. Transparent Database Cryptography & Credential Protection (`ether.graph.crypto`)
```python
class CryptoEngine:
    def open_encrypted_store(
        self, db_path: Path, passphrase_or_key: bytes
    ) -> GraphStore: ...
```
- **Zero-Dependency Default:** Pure-Python ChaCha20-Poly1305 field-level encryption (via `cryptography`) protecting `CredentialFound` secrets, `raw_data`, and sensitive `event_log` payloads, with `0o600` keyfile fallback, credential TTL expiration, and `ctypes.memset` memory zeroization.
- **Optional Integrations:** Auto-enable full-page SQLCipher and OS keyring (`secretstorage` / `keyring`) backends when those optional packages are installed, keeping `pip install ether-core` free of mandatory native C build dependencies.

### 6. Exact-Ownership WriteQueue Serialization (`ether.graph.write_queue`)
```python
class WriteQueue:
    async def enqueue_upsert(
        self, session_id: str, findings: Sequence[BaseFinding], action_id: Optional[str] = None
    ) -> UpsertResult: ...

    async def enqueue_mutation(
        self, operation_callable: Callable[[aiosqlite.Connection], Any]
    ) -> Any: ...
```
- **Clean-Break Replacement:** Replace `WriteQueueWorker` and offset slicing (`all_nids[s:e]`) with `WriteQueue` maintaining an internal reverse PIK lookup (`Dict[str, NodeId]`) so every caller receives exact, uncorrupted `UpsertResult` attribution even under heavy deduplication.
- **Full Mutation Serialization:** Route `export_session()`, `import_session()`, and schema migrations through `enqueue_mutation()`. Update all internal `GraphStore` callers and tests directly.

### 7. Two-Phase Atomic Session Sealer & Signed Audit Trail (`ether.common.session_sealer`)
```python
class SessionSealer:
    async def seal_session(
        self, session_id: str, private_key: Optional[bytes] = None
    ) -> SealReceipt: ...
```
- **Two-Phase Commit State Machine:** `ACTIVE` → `SEALING` → `COMPRESSING` → `SEALED` backed by a persistent recovery journal so crashes mid-compression recover cleanly.
- **Asymmetric Ed25519 Signing:** Signs the completed audit manifest and SHA-256 log hash chain. When `private_key` is omitted on persistent stores, auto-provisions a `0o600` node-local Ed25519 keypair under `ETHER_DATA_DIR/keys/audit_signing.key`; skips disk key creation for `:memory:` stores unless explicitly supplied.

### 8. DNS-Pinned Socket Transport & Rebinding Defense (`ether.common.transport`)
```python
class PinnedTransport:
    def create_client(
        self, scope: EngagementScope, verify_tls: bool = True
    ) -> httpx.AsyncClient: ...
```
- **Socket-Level DNS Pinning:** Resolves DNS once, validates all IPs against `EngagementScope`, pins the TCP handshake to the validated IP (preserving SNI/Host for TLS virtual hosts), and re-validates + re-pins every `301`/`302`/`307`/`308` redirect hop.
- **TLS Default:** Defaults `verify_tls=True` across `http_probe`, `imds_probe`, and `ffuf` baseline calibration, with explicit opt-out for self-signed pentest targets.

### 9. Least-Privilege Scanner Isolation (`ether.core.privilege`)
- **`PrivilegeGovernor`:** Drops Linux ambient/bounding capabilities and sets `PR_SET_NO_NEW_PRIVS` on the Python supervisor process by default on Linux.
- **Optional Isolated Backend:** Supports an opt-in UDS isolated-worker / rootless-netns execution backend when configured, with graceful fallback on macOS and unprivileged developer hosts.

### 10. Supply-Chain Security, Provenance & Reproducible Benchmarks
- **CI / Release Workflows:** Add `uv lock --check` to `.github/workflows/ci.yml`; add CycloneDX SBOM generation and Sigstore/Cosign container image signing to `.github/workflows/release.yml`.
- **Local Verification:** Add `scripts/benchmark_reproducible.py` (capturing commit, hardware, kernel, Python version, workload, variance) and `tests/security/test_adversarial_boundaries.py` (file permission races, DNS rebinding, redirect chains, SSE rate limits, and audit tampering).

---

## Phased Implementation Plan

- **Phase 1 — Core Storage & Lifecycle Integrity:** `WriteQueue` exact-ownership refactor (`write_queue.py`, `store.py`), `SessionSealer` (`session_sealer.py`), and `CryptoEngine` (`crypto.py`).
- **Phase 2 — Manifest & Adapter Redesign + `FlagFirewall`:** Purge CyGuide schemas in `manifest.py` and all 38 `tools/*/manifest.toml`; add `[flags]`, `[execution]`, and minimal `[profiles]`; upgrade `ToolAdapter` streaming/structured defaults; implement `FlagFirewall` (`ether.gateway.flags`) and wire into `ActionGateway` / `PreflightVerifier`.
- **Phase 3 — Network, Transport & Privilege Hardening:** `PinnedTransport` (`ether.common.transport`) wired into `http_probe`, `imds_probe`, `ffuf`; `SecurityMiddleware` (`ether.mcp.security`) replacing `BearerTokenAuthMiddleware`; `PluginLoader` (`ether.registry.loader`); `PrivilegeGovernor` (`ether.core.privilege`).
- **Phase 4 — Supply-Chain & Adversarial Verification:** CI/Release SBOM + Cosign + lockfile checks, `scripts/benchmark_reproducible.py`, `tests/security/test_adversarial_boundaries.py`, and full `tier0` / `fast` / `fuzz` / `mypy` / `ruff` gate pass.

## Consequences
- **Positive:** Eliminates CyGuide curriculum bloat, closes all 10 zero-trust and supply-chain gaps, guarantees exact multi-agent finding attribution, and turns `manifest.toml` + `ToolAdapter` into a fast, structured-first execution seam.
- **Trade-offs:** Purging `[modes]`/`[learning]`/`[power]` requires updating all 38 `tools/*/manifest.toml` files and internal registry/CLI/MCP tests; defaulting `verify_tls=True` requires callers scanning self-signed targets to pass the explicit opt-out flag.
