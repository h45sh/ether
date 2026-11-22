# 03: Native dnspython Coroutine Conversion

**What to build:**
Convert the `dnspython` tool adapter from spawning an external Python CLI process to executing as a native in-process `asyncio` coroutine. Update `tools/dnspython/manifest.toml` with `execution_tier = "coroutine"`. In `tools/dnspython/adapter.py`, implement `execute_action()` using `dns.asyncresolver.Resolver` to resolve A, AAAA, MX, NS, TXT, SOA, PTR, and AXFR records asynchronously. Write wire traces to `context.spool_line()`, and yield `DnsRecord` and `NetworkHost` findings. Update tests in `tests/unit/test_parsers/test_dnspython_parser.py` and write direct coroutine execution tests.

**Blocked by:** 02: Manifest Execution Tiers & Discovery (manifest.toml)

**Status:** ready-for-agent

- [ ] Update `tools/dnspython/manifest.toml` to set `execution_tier = "coroutine"`
- [ ] Implement `DNSPythonAdapter.execute_action()` in `tools/dnspython/adapter.py` using `dns.asyncresolver`
- [ ] Stream query and response lines to `context.spool_line()`
- [ ] Emit normalized `DnsRecord` and `NetworkHost` findings
- [ ] Add unit tests verifying in-process execution, wire spooling, and finding emission in `tests/unit/test_parsers/test_dnspython_parser.py`
