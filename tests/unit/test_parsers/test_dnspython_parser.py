"""Unit tests for the dnspython adapter and parser."""

from pathlib import Path
from unittest.mock import patch

import pytest

from ether.schemas.dns import DnsRecord
from ether.schemas.network import NetworkHost
from tools.dnspython.adapter import DnsPythonAdapter


@pytest.fixture
def adapter():
    return DnsPythonAdapter()


def test_dnspython_build_command(adapter):
    # 1. Target is dns.record
    dns_rec = DnsRecord.create(domain="example.com", record_type="A", value="93.184.216.34")
    cmd = adapter.build_command(dns_rec, {"raw_flags": "-t MX"})
    assert "-m" in cmd
    assert "tools.dnspython.cli" in cmd
    target_idx = cmd.index("tools.dnspython.cli") + 1
    assert cmd[target_idx] == "example.com"
    assert "--json" in cmd
    assert "-t" in cmd
    assert "MX" in cmd

    # 2. Target is network.host
    host = NetworkHost.create(ip="8.8.8.8")
    cmd_host = adapter.build_command(host, {"raw_flags": "-t PTR"})
    assert "8.8.8.8" in cmd_host
    assert "-t" in cmd_host
    assert "PTR" in cmd_host

    # 3. Missing query field raises ValueError
    empty_host = NetworkHost.create(ip="")
    empty_host.pik = {}
    with pytest.raises(ValueError, match="missing query field"):
        adapter.build_command(empty_host, {})


@pytest.mark.asyncio
async def test_dnspython_parse_output(adapter):
    fixture_path = (
        Path(__file__).parent.parent.parent / "fixtures" / "mock_tools" / "dnspython.json"
    )
    with open(fixture_path, "r", encoding="utf-8") as f:
        sample_output = f.read()

    target = DnsRecord.create(domain="example.com", record_type="A", value="93.184.216.34")
    findings = [f async for f in adapter.parse_output(sample_output, target)]

    assert len(findings) == 5
    types = [f.pik["type"] for f in findings]
    assert "A" in types
    assert "AAAA" in types
    assert "MX" in types
    assert "NS" in types
    assert "TXT" in types

    a_rec = next(f for f in findings if f.pik["type"] == "A")
    assert a_rec.pik["domain"] == "example.com"
    assert a_rec.data["value"] == "93.184.216.34"
    assert a_rec.data["resolved_ip"] == "93.184.216.34"
    assert len(a_rec.associations) == 1
    assert a_rec.associations[0].target_type == "network.host"
    assert a_rec.associations[0].target_pik["ip"] == "93.184.216.34"

    mx_rec = next(f for f in findings if f.pik["type"] == "MX")
    assert mx_rec.data["value"] == "10 mail.example.com"


def test_dnspython_execution_tier(adapter):
    assert adapter.execution_tier == "coroutine"


@pytest.mark.asyncio
async def test_dnspython_execute_action_native(adapter):
    from unittest.mock import patch

    import dns.resolver

    from ether.common.context import ExecutionContext

    spooled_lines = []

    async def fake_spool(line: str, is_error: bool = False):
        spooled_lines.append((line, is_error))

    ctx = ExecutionContext(
        action_id="act-test-dns-1",
        session_id="sess-test",
        spool_fn=fake_spool,
    )

    class DummyAnswer:
        def __init__(self, items, ttl=300):
            self.items = items
            self.ttl = ttl

        def __iter__(self):
            return iter(self.items)

    class DummyRdata:
        def __init__(self, text):
            self.text = text

        def __str__(self):
            return self.text

    async def mock_resolve(qname, rtype, *args, **kwargs):
        if rtype == "A":
            return DummyAnswer([DummyRdata("93.184.216.34")])
        elif rtype == "MX":
            return DummyAnswer([DummyRdata("10 mail.example.com")])
        raise dns.resolver.NoAnswer()

    target = DnsRecord.create(domain="example.com", record_type="A", value="")
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        findings = [
            f
            async for f in adapter.execute_action(
                target, {"raw_flags": "-t A,MX"}, ctx
            )
        ]

    # Verify findings
    assert len(findings) == 3  # DnsRecord(A), NetworkHost(93.184.216.34), DnsRecord(MX)
    dns_records = [f for f in findings if f.schema_type == "dns.record"]
    host_records = [f for f in findings if f.schema_type == "network.host"]

    assert len(dns_records) == 2
    assert len(host_records) == 1
    assert host_records[0].pik["ip"] == "93.184.216.34"

    # Verify spooling
    text_spooled = [line for line, _ in spooled_lines]
    assert any("Native DNS resolution initiated" in l for l in text_spooled)
    assert any("Querying A for example.com" in l for l in text_spooled)
    assert any("93.184.216.34" in l for l in text_spooled)


@pytest.mark.asyncio
async def test_dnspython_execute_action_ptr(adapter):
    from unittest.mock import patch

    from ether.common.context import ExecutionContext

    spooled_lines = []

    async def fake_spool(line: str, is_error: bool = False):
        spooled_lines.append((line, is_error))

    ctx = ExecutionContext(
        action_id="act-test-dns-ptr",
        session_id="sess-test",
        spool_fn=fake_spool,
    )

    class DummyAnswer:
        def __init__(self, items, ttl=300):
            self.items = items
            self.ttl = ttl

        def __iter__(self):
            return iter(self.items)

    class DummyPtrRdata:
        def __init__(self, target_str):
            self.target = target_str

    async def mock_resolve(qname, rtype, *args, **kwargs):
        if rtype == "PTR":
            return DummyAnswer([DummyPtrRdata("dns.google.")])
        raise Exception("Unexpected query")

    host_target = NetworkHost.create(ip="8.8.8.8")
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        findings = [
            f async for f in adapter.execute_action(host_target, {}, ctx)
        ]

    assert len(findings) == 1
    rec = findings[0]
    assert rec.schema_type == "dns.record"
    assert rec.pik["type"] == "PTR"
    assert rec.data["value"] == "dns.google"
    assert rec.data["resolved_ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_dnspython_execute_action_nxdomain(adapter):
    from unittest.mock import patch

    import dns.resolver

    from ether.common.context import ExecutionContext

    spooled_lines = []

    async def fake_spool(line: str, is_error: bool = False):
        spooled_lines.append((line, is_error))

    ctx = ExecutionContext(
        action_id="act-test-dns-nx",
        session_id="sess-test",
        spool_fn=fake_spool,
    )

    async def mock_resolve(qname, rtype, *args, **kwargs):
        raise dns.resolver.NXDOMAIN()

    target = DnsRecord.create(domain="nonexistent.invalid", record_type="A", value="")
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        findings = [
            f async for f in adapter.execute_action(target, {}, ctx)
        ]

    assert len(findings) == 0
    text_spooled = [line for line, _ in spooled_lines]
    assert any("does not exist (NXDOMAIN)" in l for l in text_spooled)


@pytest.mark.asyncio
async def test_dnspython_ttl_and_soa_anchor_extraction(adapter):
    """Verify that dnspython propagates record TTL and extracts SOA serial anchor."""
    import dns.resolver

    from ether.common.context import ExecutionContext

    spooled_lines = []

    async def fake_spool(line: str, is_error: bool = False):
        spooled_lines.append((line, is_error))

    ctx = ExecutionContext(
        action_id="act-test-dns-soa",
        session_id="sess-test",
        spool_fn=fake_spool,
    )

    class DummyAnswer:
        def __init__(self, items, ttl=7200):
            self.items = items
            self.ttl = ttl

        def __iter__(self):
            return iter(self.items)

    class DummySOARdata:
        def __init__(self):
            self.serial = 2026112201

        def __str__(self):
            return "ns1.example.com admin.example.com 2026112201 7200 3600 1209600 3600"

    async def mock_resolve(qname, rtype, *args, **kwargs):
        if rtype == "SOA":
            return DummyAnswer([DummySOARdata()], ttl=7200)
        raise dns.resolver.NoAnswer()

    target = DnsRecord.create(domain="example.com", record_type="SOA", value="")
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        findings = [
            f
            async for f in adapter.execute_action(
                target, {"raw_flags": "-t SOA"}, ctx
            )
        ]

    assert len(findings) == 1
    soa_rec = findings[0]
    assert soa_rec.ttl_seconds == 7200
    assert soa_rec.anchor_hash == "soa:2026112201"

