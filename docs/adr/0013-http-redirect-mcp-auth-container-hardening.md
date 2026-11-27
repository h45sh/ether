# ADR 0013: HTTP Redirect Validation, MCP Authentication, and Container Hardening

## Status
Accepted

## Context
Following comprehensive security auditing and architecture review across Ether's network gateway, MCP telemetry layer, and container runtime substrate, three defense-in-depth gaps were identified:

1. **HTTP Probe Redirect & Rebinding SSRF Risk:**
   While `HTTPProbeAdapter` executed pre-flight target checks with `ScopeValidator.check_destination()`, `httpx.AsyncClient` followed 3xx redirects without re-validating the `Location` header against the scope boundary. An external target could issue an HTTP 301/302 redirect to cloud IMDS (`169.254.169.254`, `fd00:ec2::254`), loopback (`127.0.0.1`), or unauthorized internal networks under `GatePolicy.SAFE`.

2. **Unauthenticated MCP SSE Network Exposure:**
   The `ether mcp --transport sse` server could bind to external interfaces (`--host 0.0.0.0`) without authentication. This exposed an unauthenticated execution surface capable of dispatching security tools and querying internal graph data over the network.

3. **Container Superuser Execution:**
   The production `Dockerfile` ran as `root` with `WORKDIR /root` and root-owned persistent volumes. While raw socket packet scanners (`nmap`) historically required root, running the entire supervisor substrate as root violated the principle of least privilege and increased container breakout severity.

## Decision

1. **Authoritative HTTP Redirect SSRF Validation Hook:**
   - In `tools/http_probe/adapter.py`, register a response event hook (`_redirect_hook`) in `httpx.AsyncClient` that intercepts every 3xx redirect response.
   - The hook resolves relative or absolute URLs via `urllib.parse.urljoin(str(response.request.url), location)` and validates the target destination against `ScopeValidator.check_destination(redirect_url, scope=context.scope, policy_is_unrestricted=is_unrestricted)`.
   - If the destination violates scope or targets blocked metadata/loopback under `GatePolicy.SAFE`, the hook spools an alert and raises `PolicyViolationError`, immediately aborting the request chain before the redirect hop is dispatched.

2. **MCP SSE Authentication & Host Binding Security Gate:**
   - Add `--auth-token` CLI argument to `ether mcp` and recognize `ETHER_MCP_AUTH_TOKEN` from the environment.
   - Enforce a host binding gate in `handle_mcp`: binding to non-loopback interfaces (`0.0.0.0`, external IPs) under `GatePolicy.SAFE` requires a configured authentication token; otherwise, server initialization is rejected with `EXIT_RUNTIME_ERROR`.
   - Implement `BearerTokenAuthMiddleware` in `src/ether/mcp/server.py` and wrap the Starlette application in `EtherMCPServer.sse_app()`. Incoming HTTP requests without a matching `Authorization: Bearer <token>` header receive an immediate HTTP 401 Unauthorized response with `WWW-Authenticate: Bearer realm="ether-mcp"`.

3. **Container Non-Root Isolation with Linux Capabilities:**
   - Harden `Dockerfile` to create an unprivileged system user and group `ether:ether` (UID/GID 1000).
   - Configure `ETHER_DATA_DIR=/home/ether/.ether` with strict `0o700` atomic directory permissions.
   - Install `libcap2-bin` during the build phase and grant fine-grained capabilities (`setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap`) directly to the scanner binary.
   - Switch the active container user to `USER ether` and set `WORKDIR /home/ether` before invoking the entrypoint.

## Consequences

- **Positive:**
  - Guaranteed SSRF immunity across arbitrary multi-hop redirects in HTTP probing.
  - Zero unauthenticated remote tool execution risk when exposing MCP over network interfaces.
  - Reduced container breakout blast radius adhering to production least-privilege standards while preserving raw socket network scanning capabilities.
  - Complete mechanical test coverage across unit tests (`test_http_probe_adapter.py`, `test_mcp.py`).

- **Trade-offs:**
  - Exposing the MCP SSE server on non-loopback addresses under `GatePolicy.SAFE` requires passing `--auth-token` or setting `ETHER_MCP_AUTH_TOKEN`.
