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
   Subprocess environments must be scrubbed (`sanitize_subprocess_env`) of operator secrets (`ETHER_*`, `CYGUIDE_*`, `OPENAI_*`, `ANTHROPIC_*`, `AWS_*`, `GITHUB_*`, `VAULT_TOKEN`, `SSH_PRIVATE_KEY`). Flaws where external CLI tools can read operator API tokens from child `/proc/<PID>/environ` are in-scope.

3. **Network Gateways & Cloud Metadata SSRF Protection**:
   Ether enforces `GatePolicy.SAFE` by default: target validation, Link-Local and cloud metadata blocking (`169.254.0.0/16`, `fd00:ec2::254`, `100.100.100.200`, `metadata.google.internal`). Bypasses that trick the gateway into dispatching requests to cloud metadata services or bypassing target CIDR boundary checks under `GatePolicy.SAFE` are considered high-severity security issues.

4. **AI Prompt Injection Boundary**:
   Untrusted scanner outputs passed to AI models must be wrapped inside `<untrusted_scan_output>...</untrusted_scan_output>` boundary tags with closing tag breakout neutralization (`</untrusted_scan_output>` replaced with `<\/untrusted_scan_output>`) and strict length bounding (`max_chars=100_000`). Discovered credentials remain unmutated in the entity graph for technical fidelity, with sensitive values masked at presentation time unless `--unmask` is explicitly supplied. Exploits that achieve prompt injection override or sandbox breakout are in-scope.

5. **Session Database Hardening & Parameterization**:
   Exported and internal SQLite databases enforce 100% parameterized SQL queries (`?`), `PRAGMA foreign_keys = ON;`, and `PRAGMA journal_mode = WAL;`. Deserialization flaws leading to path traversal, arbitrary file writes, or trigger execution are in-scope.

6. **Local Filesystem Permissions**:
   Sensitive exported archives, operator state, and credential caches enforce atomic `0o600` permissions (`atomic_create_file` or `os.open` with `O_CREAT | O_WRONLY | O_TRUNC`) to prevent TOCTOU permission races.

7. **Forensic Integrity & Audit Chain of Custody**:
   All executed actions generate cryptographically hash-chained `AuditRecord` entries in `~/.ether/audit/{session_id}.jsonl`. Each record links the previous block hash and verifies raw log file integrity (`SHA-256`), with automatic gzip compaction upon session closure. Tampering with audit logs or manifests is detectable via `ether session verify-audit`.
