# 04: Native http_probe Adapter with SSRF Pre-Connect Defense

**What to build:**
Create the `http_probe` tool adapter for high-throughput in-process HTTP discovery. Add `httpx>=0.27.0` to `dependencies` in `pyproject.toml`. Create `tools/http_probe/manifest.toml` with `execution_tier = "coroutine"`. In `tools/http_probe/adapter.py`, implement `execute_action()` using `httpx.AsyncClient` with bounded concurrency (`max_connections=50`) and socket timeouts (5s connect, 10s read). Enforce pre-connect DNS resolution and abort immediately with `PolicyViolationError` if the destination maps to cloud metadata (`169.254.169.254`, `fd00:ec2::254`), loopback, or unauthorized CIDR under `GatePolicy.SAFE`. Extract status code, headers, `<title>`, server banner, and TLS details, write wire traces to `context.spool_line()`, and yield `NetworkService`, `WebEndpoint`, and `WebTechnology` findings.

**Blocked by:** 02: Manifest Execution Tiers & Discovery (manifest.toml)

**Status:** completed

- [x] Add `httpx>=0.27.0` to `dependencies` in `pyproject.toml`
- [x] Create `tools/http_probe/manifest.toml` declaring `execution_tier = "coroutine"`
- [x] Implement `HTTPProbeAdapter.execute_action()` in `tools/http_probe/adapter.py`
- [x] Implement pre-connect IP resolution and SSRF defense under `GatePolicy.SAFE`
- [x] Stream request and response headers to `context.spool_line()`
- [x] Emit `NetworkService`, `WebEndpoint`, and `WebTechnology` findings
- [x] Add hermetic unit and SSRF tests in `tests/unit/test_parsers/test_http_probe_adapter.py`
