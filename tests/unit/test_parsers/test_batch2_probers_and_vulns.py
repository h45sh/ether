"""Unit tests for Batch 2 tool adapters (mysql_probe, postgres_probe, redis_probe, imds_probe, cve_search, wpscan)."""

import pytest

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.gateway.gate import GatePolicy
from ether.schemas.network import NetworkHost, NetworkService
from ether.schemas.web import WebEndpoint
from tools.cve_search.adapter import CveSearchAdapter
from tools.imds_probe.adapter import ImdsProbeAdapter
from tools.mysql_probe.adapter import MysqlProbeAdapter
from tools.postgres_probe.adapter import PostgresProbeAdapter
from tools.redis_probe.adapter import RedisProbeAdapter
from tools.wpscan.adapter import WpscanAdapter


@pytest.mark.fast
def test_mysql_probe_validation_and_build():
    adapter = MysqlProbeAdapter()
    assert adapter.validate_install() is True
    target = NetworkService.create(host_ip="127.0.0.1", port=3306)
    cmd = adapter.build_command(target, {})
    assert "mysql_probe" in cmd
    assert "127.0.0.1" in cmd


@pytest.mark.fast
def test_postgres_probe_validation_and_build():
    adapter = PostgresProbeAdapter()
    assert adapter.validate_install() is True
    target = NetworkService.create(host_ip="127.0.0.1", port=5432)
    cmd = adapter.build_command(target, {})
    assert "postgres_probe" in cmd
    assert "127.0.0.1" in cmd


@pytest.mark.fast
def test_redis_probe_validation_and_build():
    adapter = RedisProbeAdapter()
    assert adapter.validate_install() is True
    target = NetworkService.create(host_ip="127.0.0.1", port=6379)
    cmd = adapter.build_command(target, {})
    assert "redis_probe" in cmd
    assert "127.0.0.1" in cmd


@pytest.mark.asyncio
async def test_imds_probe_ssrf_safety_gate():
    adapter = ImdsProbeAdapter()
    target = NetworkHost.create(ip="169.254.169.254")

    # Under GatePolicy.SAFE, must raise PolicyViolationError
    context_safe = ExecutionContext(
        action_id="act-test",
        session_id="sess-test",
        policy=GatePolicy.SAFE,
        runner=None,
    )
    with pytest.raises(PolicyViolationError, match="forbidden under GatePolicy.SAFE"):
        async for _ in adapter.execute_action(target, {}, context_safe):
            pass


@pytest.mark.asyncio
async def test_cve_search_parser():
    adapter = CveSearchAdapter()
    target = NetworkService.create(
        host_ip="10.0.0.1", port=80, service_name="apache", version="2.4.49"
    )

    raw_json = (
        '[{"id": "CVE-2021-41773", "summary": "Path Traversal in Apache 2.4.49", "cvss": 9.8}]\n'
    )
    findings = [f async for f in adapter.parse_output(raw_json, target)]
    assert len(findings) == 1
    assert findings[0].pik["vuln_id"] == "CVE-2021-41773"
    assert findings[0].data["severity"] == "critical"


@pytest.mark.asyncio
async def test_wpscan_parser():
    adapter = WpscanAdapter()
    target = WebEndpoint.create(url="https://wp.example.com")

    raw_text = "[!] 2 vulnerabilities found:\n[+] CVE-2023-1234\n[+] CVE-2023-5678\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 2
    cves = [f.pik["vuln_id"] for f in findings]
    assert "CVE-2023-1234" in cves
    assert "CVE-2023-5678" in cves
