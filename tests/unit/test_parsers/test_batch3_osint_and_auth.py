"""Unit tests for Batch 3 tool adapters (zmap, rustscan, amass, crtsh, dnsrecon, hydra, ghauri, cloud_enum)."""

import pytest

from ether.schemas.dns import DomainInfo
from ether.schemas.network import NetworkHost, NetworkService
from ether.schemas.web import WebEndpoint
from tools.amass.adapter import AmassAdapter
from tools.cloud_enum.adapter import CloudEnumAdapter
from tools.crtsh.adapter import CrtshAdapter
from tools.dnsrecon.adapter import DnsreconAdapter
from tools.ghauri.adapter import GhauriAdapter
from tools.hydra.adapter import HydraAdapter
from tools.rustscan.adapter import RustscanAdapter
from tools.zmap.adapter import ZmapAdapter


@pytest.mark.asyncio
async def test_zmap_parser():
    adapter = ZmapAdapter()
    target = NetworkHost.create(ip="10.0.0.1")

    raw_text = "10.0.0.1\n10.0.0.2\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 4  # 2 hosts + 2 services


@pytest.mark.asyncio
async def test_rustscan_parser():
    adapter = RustscanAdapter()
    target = NetworkHost.create(ip="10.0.0.1")

    raw_text = "Open 10.0.0.1:22\nOpen 10.0.0.1:80\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 2
    ports = [f.pik["port"] for f in findings]
    assert 22 in ports
    assert 80 in ports


@pytest.mark.asyncio
async def test_amass_parser():
    adapter = AmassAdapter()
    target = DomainInfo.create(domain="example.com")

    raw_text = '{"name":"api.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}]}\n'
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 2
    types = [f.schema_type for f in findings]
    assert "domain.info" in types
    assert "network.host" in types


@pytest.mark.fast
def test_crtsh_adapter_contract():
    adapter = CrtshAdapter()
    assert adapter.validate_install() is True
    target = DomainInfo.create(domain="example.com")
    cmd = adapter.build_command(target, {})
    assert "crtsh" in cmd
    assert any(arg == target.pik["domain"] for arg in cmd)


@pytest.mark.asyncio
async def test_dnsrecon_parser():
    adapter = DnsreconAdapter()
    target = DomainInfo.create(domain="example.com")

    raw_text = "[*] A mail.example.com 1.2.3.4\n[*] MX mail.example.com 1.2.3.4\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 2
    assert findings[0].pik["type"] == "A"
    assert findings[1].pik["type"] == "MX"


@pytest.mark.asyncio
async def test_hydra_parser():
    adapter = HydraAdapter()
    target = NetworkService.create(host_ip="192.168.1.100", port=22, service_name="ssh")

    raw_text = "[22][ssh] host: 192.168.1.100   login: admin   password: secretpassword\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 1
    assert findings[0].schema_type == "credential.found"
    assert findings[0].pik["username"] == "admin"
    assert findings[0].data["password"] == "secretpassword"


@pytest.mark.asyncio
async def test_ghauri_parser():
    adapter = GhauriAdapter()
    target = WebEndpoint.create(url="https://example.com/item.php?id=1")

    raw_text = "Parameter 'id' is vulnerable to SQL injection.\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 1
    assert findings[0].schema_type == "web.vulnerability"
    assert findings[0].data["vuln_type"] == "sql_injection"


@pytest.mark.asyncio
async def test_cloud_enum_parser():
    adapter = CloudEnumAdapter()
    target = DomainInfo.create(domain="example.com")

    raw_text = "[+] OPEN AWS Bucket: example-backups.s3.amazonaws.com\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 1
    assert findings[0].schema_type == "cloud.asset"
    assert findings[0].pik["provider"] == "aws"
    assert findings[0].data["public_access"] is True
