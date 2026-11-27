# Security Policy

## Supported Versions

Ether receives active security updates, vulnerability patches, and invariant audit fixes on the current default release branch and latest PyPI release.

| Release Channel | Supported | Notes |
| :--- | :---: | :--- |
| **Latest Release / Default Branch (`main`)** | **Yes** | Active security support, AST invariant enforcement, and patches. |
| **Prior Releases** | **Best Effort** | Security fixes are backported or rolled into the next minor/patch release. |

We recommend always running the latest packaged release (`pip install -U ether-core`) or pulling the latest container image (`ghcr.io/h45sh/ether:latest`).

---

## Reporting a Vulnerability

The Ether maintainers take security and process isolation seriously. If you discover a vulnerability, potential security bug, or weakness in Ether (including command injection vectors in tool adapters, sandbox breakouts, SSRF filter bypasses, credential leakage, or prompt injection flaws), please do not report it through a public GitHub issue.

### Preferred Reporting Channel

* **GitHub Private Vulnerability Reporting**: Navigate to the [Ether Security Advisory tab](https://github.com/h45sh/ether/security/advisories/new) and submit a private report.
* **Direct Maintainer Contact**: If the advisory portal is unavailable, contact the project maintainer directly at `harshwardhan@h45sh.com` with the subject line `[SECURITY] Ether Vulnerability Report`.

### What to Include

To help us assess and resolve the issue quickly, please provide:
1. A clear description of the vulnerability and its potential impact.
2. Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
3. The affected Ether version, operating system environment, and execution context (CLI vs MCP server).
4. Any potential mitigations or remediation patches you have identified.

### Response Timeline

* **Acknowledgment**: Within 48 hours of initial receipt.
* **Triage & Assessment**: Within 5 business days, confirming whether the report is accepted or requires further detail.
* **Remediation & Advisory Release**: A coordinated release date will be scheduled once a patch is mechanically verified. We aim to release critical fixes within 14 days of confirmation.

Credit will be given in the release notes and security advisories for responsibly disclosed vulnerabilities, unless the reporter requests anonymity.

---

## Security Architecture & Scope

Ether operates as a headless reactive process supervisor, AST validator, and deterministic graph telemetry substrate executing external cybersecurity binaries on the local host. When assessing potential vulnerabilities, consider the following threat model boundaries:

1. **Process Isolation & Pure Argument Vectors**:
   Ether tool adapters must always pass arguments as structured argument lists (`List[str]`) directly to `asyncio.create_subprocess_exec` rather than invoking a shell with `shell=True`. Vulnerabilities where arbitrary target parameters or unescaped macro tokens lead to unintended shell execution on the host are in-scope.

2. **Environment Sanitization & Credential Protection**:
   Subprocess environments must be scrubbed (`sanitize_subprocess_env`) of operator secrets (`ETHER_*`, `CYGUIDE_*`, `OPENAI_*`, `ANTHROPIC_*`, `GROQ_*`, `DEEPSEEK_*`, `AWS_*`, `GITHUB_*`, `SSH_*`, `AZURE_*`, `DOCKER_*`, `NPM_*`, `GOOGLE_APPLICATION_CREDENTIALS`, `DATABASE_URL`, `VAULT_TOKEN`, and `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_API_KEY`). Flaws where external CLI tools can read operator API tokens from child `/proc/<PID>/environ` are in-scope.

3. **Network Gateways & Cloud Metadata SSRF Protection**:
   Ether enforces `GatePolicy.SAFE` by default: target validation, Link-Local and cloud metadata blocking (`169.254.0.0/16`, `fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`), and loopback blocking (`allow_loopback=False` by default unless explicitly authorized via `EngagementScope`). Both `ActionGateway` and `PreflightVerifier` invoke `ScopeValidator.check_destination()` DNS resolution (blocking `*.nip.io`, `localtest.me`, and alternate hex/octal/decimal IP encodings) and inspect tokenized `--flags` values (including joined, colon-delimited, and comma-delimited forms). Bypasses that trick the gateway into dispatching requests to cloud metadata services or bypassing target CIDR boundary checks under `GatePolicy.SAFE` are considered high-severity security issues.

4. **AI Prompt Injection Boundary**:
   Untrusted scanner outputs passed to AI models must be wrapped inside `<untrusted_scan_output>...</untrusted_scan_output>` boundary tags with case-insensitive breakout neutralization (`<(?:/\s*)?untrusted_scan_output\b[^>]*>`, covering whitespace and attribute variants on opening and closing tags) and strict length bounding (`max_chars=100_000`). Discovered credentials remain unmutated in the entity graph for technical fidelity, with sensitive values masked at presentation time unless `--unmask` is explicitly supplied. Exploits that achieve prompt injection override or sandbox breakout are in-scope.

5. **Session Database Hardening & Parameterization**:
   Exported and internal SQLite databases enforce 100% parameterized SQL queries (`?`), `PRAGMA foreign_keys = ON;`, and `PRAGMA journal_mode = WAL;`. Deserialization flaws leading to path traversal, arbitrary file writes, or trigger execution are in-scope.

6. **Local Filesystem Permissions**:
   Sensitive exported archives, operator state, and credential caches enforce atomic `0o600` permissions (`atomic_create_file` via temp-file + `0o600` + `os.replace`, including overwrites) to prevent TOCTOU permission races. `GraphStore` creates database directories with `0o700` and pre-creates database files atomically with `0o600`.

7. **Forensic Integrity & Signed Audit Chain of Custody**:
   All executed actions generate cryptographically hash-chained `AuditRecord` entries in `~/.ether/audit/{session_id}.jsonl`. Session closure is governed by `SessionSealer` (`ether.common.session_sealer`), a two-phase atomic state machine (`ACTIVE` → `SEALING` → `COMPRESSING` → `SEALED`) with a recovery journal and Ed25519 signature over the completed audit manifest (`seal_receipt.json`). Tampering with audit logs, manifests, or receipts is detectable via `ether session verify-audit` and `SessionSealer.verify_seal()`.

8. **DNS-Pinned Socket Transport & Redirect SSRF Defense**:
   Per ADR 0013 and ADR 0016, `PinnedTransport` (`ether.common.transport`) resolves DNS once, validates resolved IPs against `EngagementScope`, pins the TCP handshake directly to the validated IP (preserving TLS SNI and defaulting `verify_tls=True`), and re-validates every `301`/`302`/`303`/`307`/`308` redirect hop before following.

9. **Enterprise MCP Gate & Scoped Transport Authentication**:
   `SecurityMiddleware` (`ether.mcp.security`) protects MCP HTTP/SSE endpoints with constant-time HMAC-SHA256 scoped tokens (`telemetry:read`, `graph:query`, `tool:execute`, `session:mutate`), per-IP leaky-bucket rate limiting (`429`), strict CORS origin allowlisting (`403`), and optional mTLS client certificate verification, while `stdio` runs as a local-operator `AuthContext`.

10. **FlagFirewall, Plugin Attestation, Database Cryptography & Privilege Isolation**:
    * **Subprocess Argument Firewall (`ether.gateway.flags.FlagFirewall`):** Derives strict AST flag allowlists/blocklists from each tool's `manifest.toml` `[flags]` contract under `GatePolicy.SAFE` and neutralizes shell metacharacters across all policies.
    * **Cryptographic Plugin Attestation (`ether.registry.loader.PluginLoader`):** Verifies first-party bundled `tools/*` adapters against `tools/bundle_lock.json` (SHA-256 of `manifest.toml` + `adapter.py`), enforces Ed25519 `.py.sig` + `.toml.sha256` attestation for external plugins in `STRICT` mode, and runs AST safety checks (`eval`/`exec`/restricted imports) before loading any adapter.
    * **Transparent Field Encryption (`ether.graph.crypto.CryptoEngine`):** Encrypts `CredentialFound` secrets and `raw_data` at rest via ChaCha20-Poly1305 (with `ctypes.memset` memory zeroization, TTL expiration, and optional SQLCipher/OS keyring support).
    * **Least-Privilege Execution (`ether.core.privilege.PrivilegeGovernor`):** Drops Linux ambient capabilities and enforces `PR_SET_NO_NEW_PRIVS` on the Python supervisor process, with optional rootless netns / UDS isolated scanner worker support. The official container runs as unprivileged user `ether` (UID/GID 1000) with `0o700` persistent volume permissions.
    * **Hardened Container Fallback (`ether.core.container.ContainerizedToolRunner`):** Defaults to `--network=none` (with `--network=bridge` opt-in, never `--network=host`), `--security-opt=no-new-privileges`, `--pids-limit=256`, CPU/memory quotas, and requires `@sha256:` digest-pinned images unless `ETHER_CONTAINER_ALLOW_MUTABLE_TAG=1` is set.
    * **MCP Scoped Authorization (`ether.mcp.security`):** Every MCP tool handler enforces explicit `OperationType` scopes. Static-admin bearer authentication is disabled by default (`MCPSettings.allow_static_admin = False`) and capped by `MCPSettings.static_admin_scopes` when enabled.
    * **Credential Lifecycle & Export Redaction (`ether.graph.crypto` / `ether.graph.store`):** Encrypts credential fields with key-versioned ChaCha20-Poly1305 (`enc:chacha20v1:<key_id>:...`) supporting key rotation, redacts expired credentials (`[EXPIRED]`) on read, and redacts sensitive credential fields (`[REDACTED]`) by default in `GraphStore.export_session()`.
