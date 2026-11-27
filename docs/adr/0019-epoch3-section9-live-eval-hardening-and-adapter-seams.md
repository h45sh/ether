# ADR 0019: Epoch 3 Section 9 — Live Evaluation Hardening & Adapter Seam Fixes

## Status
Accepted (Ready for Implementation)

## Context
Following [ADR 0018](0018-pre-epoch4-sealing-audit-identity-and-cli-seams.md) and live Run 6 evaluations ([master_ether_evaluation_report.html](../../reports/run_6/master_ether_evaluation_report.html)), four **Epoch 3, Section 9** items were surfaced and resolved through design review:

1. **First-Party Bundled Adapter Verification in `STRICT` Trust Mode (`ether.registry.loader`):** `ether doctor` and `ether run` fail out-of-the-box under default `PluginTrustMode.STRICT` (`Missing manifest SHA-256 digest for '.../manifest.toml' in STRICT mode`) because bundled `tools/*` adapters do not ship `.toml.sha256` / `.py.sig` sidecars, forcing operators to set `ETHER_PLUGIN_TRUST_MODE=dev`.
2. **Uniform Target & Port Resolution in `TlsProbeAdapter` (`tools/tls_probe/adapter.py`):** Running `ether run tls_probe <host> --flags "-p 8443"` ignores `-p`/`--port` (and `tools/tls_probe/manifest.toml` has `[flags] allowed = []`) and connects to `:443`, failing against non-443 TLS services.
3. **Policy-Gated TLS Verification Override in `HttpProbeAdapter` (`tools/http_probe/adapter.py`):** `http_probe` against self-signed lab/red-team HTTPS endpoints fails with `CERTIFICATE_VERIFY_FAILED` even when `--policy unrestricted` and `--flags "-k"` are passed, because `-k`/`--insecure` is not parsed from `flags` and `SAFE` mode must still fail closed on `verify_tls=False`.
4. **Two-Stage Adaptive `NmapAdapter` Execution & Partial-Result Flushing (`tools/nmap/adapter.py`):** Combined discovery + `-sV` scans over high-latency VPN tunnels exceed the default execution timeout and return `status="running", findings_count=0` instead of streaming port discoveries first and salvaging partial XML on timeout.

---

## Decision

### 1. First-Party Bundled Adapter Verification (`ether.registry.loader` & `tools/bundle_lock.json`)
- **Tier 1 Boundary:** Keep `ether.registry.registry.ToolRegistry` untouched; localize bundled-vs-external provenance and lockfile verification inside `PluginLoader.load_verified_adapter()`.
- **Bundled Lockfile (`tools/bundle_lock.json`):**
  - Store SHA-256 digests of both `manifest.toml` and `adapter.py` for every first-party `tools/*` adapter in `tools/bundle_lock.json` (automatically packaged into wheels via `packages = ["src/ether", "tools"]` in `pyproject.toml`).
  - Provide `scripts/update_bundle_lock.py` to regenerate `tools/bundle_lock.json` deterministically.
- **Verification Semantics in `PluginLoader`:**
  - **First-party bundled adapters** (resolved `adapter_path` and `manifest_path` inside the package's bundled `tools/` root): under `PluginTrustMode.STRICT`, verify `manifest.toml` and `adapter.py` SHA-256 hashes against `tools/bundle_lock.json` plus `_check_adapter_ast()`. Fail closed on missing entry or hash mismatch (e.g., local tampering) unless `ETHER_PLUGIN_TRUST_MODE=dev`.
  - **External / third-party plugins:** Continue requiring `.toml.sha256` and Ed25519 `.py.sig` (verified against `trusted_public_keys`) plus `_check_adapter_ast()` in `PluginTrustMode.STRICT`.
- **Tier 0 Drift Gate:** Add a `pytest -m tier0` test failing whenever any `tools/*/manifest.toml` or `tools/*/adapter.py` drifts from `tools/bundle_lock.json`.

### 2. Uniform Target & Port Resolution (`tools/tls_probe/`)
- **Manifest Contract:** Add `"-p"` and `"--port"` to `tools/tls_probe/manifest.toml` under `[flags].allowed` so `FlagFirewall` permits them in both `GatePolicy.SAFE` and `GatePolicy.UNRESTRICTED`.
- **Port Resolution Precedence in `TlsProbeAdapter`:**
  1. Explicit `-p <port>` / `--port <port>` / `--port=<port>` / `-p<port>` in `params["flags"]`.
  2. Port parsed from URL or `host:port` target.
  3. `params["port"]` if provided.
  4. Default `443`.
- Validate resolved port in `1..65535` (raising `ValueError` on invalid/out-of-range ports) while preserving `ScopeValidator.check_destination()` SSRF checks under `GatePolicy.SAFE`.

### 3. Policy-Gated TLS Verification Override (`tools/http_probe/`)
- **Immutable `SAFE` Default:** Keep `verify_tls=True` as the default in `PinnedTransport` and `HttpProbeAdapter`.
- **Fail-Closed `SAFE` Enforcement:**
  - `FlagFirewall` continues blocking `-k` / `--insecure` under `GatePolicy.SAFE` (`tools/http_probe/manifest.toml` keeps `[flags].allowed = []`).
  - Inside `HttpProbeAdapter.execute_action()`, if `params.get("verify_tls")` is explicitly `False` (or `-k`/`--insecure` is present) while `context.policy` is `SAFE`, raise `PolicyViolationError`.
- **`UNRESTRICTED` Override:** Under `GatePolicy.UNRESTRICTED`, honor `-k` / `--insecure` in `params["flags"]` as well as `params["verify_tls"] = False`, configure `PinnedTransport(..., verify_tls=False)` and the certificate-extraction `ssl_ctx`, and record `tls_verified=False` in the emitted `WebEndpoint` metadata.

### 4. Two-Stage Adaptive `NmapAdapter` Execution (`tools/nmap/adapter.py`)
- **Trigger Condition:** In `NmapAdapter.execute_action()`, engage two-stage adaptive execution **only** when `-sV` or `-A` is requested **without** a narrow explicit `-p` port list (e.g., no `-p`, or `-p-`, or `--top-ports > 20`, or port ranges). Narrow explicit `-p` scans (such as `-sV -p 80,443`) remain single-stage.
- **Stage Timeout Budget & Execution Flow:**
  - Allocate `35%` of total `timeout_sec` (clamped between `10.0s` and `45.0s`) to **Stage 1** (port discovery without `-sV`/`-A`), yielding discovered `NetworkService` findings immediately upon completion.
  - **Zero-Port Short-Circuit:** If Stage 1 finds `0` open ports, skip Stage 2 completely and return cleanly.
  - **Stage 1 Timeout:** If Stage 1 times out, salvage any open ports from partial XML via `salvage_xml_elements`, yield them, and stop without launching Stage 2.
  - **Stage 2 (`-sV` Enrichment):** Run Stage 2 exclusively against the discovered open ports (`-p <open_ports>`) using the remaining timeout budget, salvaging partial XML findings if Stage 2 times out.

---

## Acceptance Criteria
1. **Bundled Adapter Verification:**
   - `ether doctor` and `ether run` succeed out-of-the-box in `PluginTrustMode.STRICT` without `ETHER_PLUGIN_TRUST_MODE=dev`.
   - Modifying a bundled `adapter.py` or `manifest.toml` without updating `tools/bundle_lock.json` fails closed in `STRICT` mode and fails `pytest -m tier0`.
   - External plugins without `.toml.sha256` + `.py.sig` continue to be rejected in `STRICT` mode.
2. **TlsProbeAdapter:**
   - `ether run tls_probe <host> --flags "-p 8443"` connects to port `8443` in both `SAFE` and `UNRESTRICTED` modes; invalid ports fail fast.
3. **HttpProbeAdapter:**
   - `http_probe` with `-k` / `--insecure` or `verify_tls=False` fails closed under `GatePolicy.SAFE`, and succeeds against self-signed HTTPS endpoints under `GatePolicy.UNRESTRICTED` with `tls_verified=False` recorded.
4. **NmapAdapter:**
   - Broad `-sV` scans execute Stage 1 -> Stage 2 (`-p <open_ports>`), short-circuit on 0 open ports, stop after salvaging if Stage 1 times out, and salvage Stage 2 partial XML on Stage 2 timeout; narrow `-sV -p 80,443` runs single-stage.
5. **CI Parity Gate:** `.venv/bin/ruff check .`, `.venv/bin/ruff format --check .`, `.venv/bin/mypy src/ether`, and `.venv/bin/pytest` pass with 0 regressions.
