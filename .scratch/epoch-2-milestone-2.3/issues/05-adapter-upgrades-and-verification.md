# 05: Adapter Upgrades (http_probe & dnspython) and Full Verification

**What to build:**
Upgrade native in-process coroutine adapters to extract cryptographic and structural anchors. In `tools/http_probe/adapter.py`, extract the server's X.509 peer certificate SHA-256 fingerprint on HTTPS/TLS endpoints and attach as `tls:<fingerprint>`, and compute SHA-256 of `/favicon.ico`. In `tools/dnspython/adapter.py`, extract SOA serial numbers (`soa:<serial>`) and set finding `ttl_seconds` directly from DNS record TTLs. Run the complete mechanical verification matrix (`pytest -m tier0`, `pytest -m fast`, `pytest -m fuzz`, full `pytest`, and `ruff check .`) ensuring zero regressions.

**Blocked by:** 04: Telemetry Action Diff Updates & MCP Integration

**Status:** completed

- [x] Update `tools/http_probe/adapter.py` to extract TLS peer certificate SHA-256 fingerprints and favicon hashes
- [x] Update `tools/dnspython/adapter.py` to extract SOA serial numbers and propagate DNS TTLs
- [x] Add unit tests verifying anchor extraction in `tests/unit/test_parsers/test_http_probe_adapter.py` and `tests/unit/test_parsers/test_dnspython_parser.py`
- [x] Verify full test suite (`pytest -m tier0`, `pytest -m fast`, `pytest -m fuzz`, full `pytest`) passes green
- [x] Verify Ruff linter (`ruff check .`) passes with zero warnings
