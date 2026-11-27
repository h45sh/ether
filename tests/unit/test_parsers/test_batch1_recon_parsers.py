"""Unit tests for Batch 1 Recon & Web tool adapters (naabu, masscan, katana, kiterunner, feroxbuster, arjun)."""

import pytest

from ether.schemas.network import NetworkHost, NetworkNetblock
from ether.schemas.web import WebEndpoint
from tools.arjun.adapter import ArjunAdapter
from tools.feroxbuster.adapter import FeroxbusterAdapter
from tools.katana.adapter import KatanaAdapter
from tools.kiterunner.adapter import KiterunnerAdapter
from tools.masscan.adapter import MasscanAdapter
from tools.naabu.adapter import NaabuAdapter


@pytest.mark.asyncio
async def test_naabu_parser():
    adapter = NaabuAdapter()
    target = NetworkHost.create(ip="10.0.0.1")

    raw_json = '{"ip":"10.0.0.1","port":80}\n{"ip":"10.0.0.1","port":443}\n'
    findings = [f async for f in adapter.parse_output(raw_json, target)]
    assert len(findings) == 2
    assert findings[0].pik["port"] == 80
    assert findings[1].pik["port"] == 443

    raw_text = "10.0.0.1:8080\n"
    findings_text = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings_text) == 1
    assert findings_text[0].pik["port"] == 8080


@pytest.mark.asyncio
async def test_masscan_parser():
    adapter = MasscanAdapter()
    target = NetworkNetblock.create(cidr="192.168.1.0/24")

    raw_text = "Discovered open port 80/tcp on 192.168.1.50\nDiscovered open port 443/tcp on 192.168.1.50\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 2
    assert findings[0].pik["host_ip"] == "192.168.1.50"
    assert findings[0].pik["port"] == 80


@pytest.mark.asyncio
async def test_katana_parser():
    adapter = KatanaAdapter()
    target = WebEndpoint.create(url="https://example.com")

    raw_jsonl = '{"request":{"endpoint":"https://example.com/api/v1"}}\n{"endpoint":"https://example.com/login"}\n'
    findings = [f async for f in adapter.parse_output(raw_jsonl, target)]
    assert len(findings) == 2
    urls = [f.pik["url"] for f in findings]
    assert "https://example.com/api/v1" in urls
    assert "https://example.com/login" in urls


@pytest.mark.asyncio
async def test_kiterunner_parser():
    adapter = KiterunnerAdapter()
    target = WebEndpoint.create(url="https://api.example.com")

    raw_text = "[200] [  450B] https://api.example.com/v1/users\n[403] [  120B] https://api.example.com/admin\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 2
    assert findings[0].data["status_code"] == 200
    assert findings[0].pik["url"] == "https://api.example.com/v1/users"


@pytest.mark.asyncio
async def test_feroxbuster_parser():
    adapter = FeroxbusterAdapter()
    target = WebEndpoint.create(url="https://example.com")

    raw_json = '{"url":"https://example.com/dashboard","status":200}\n'
    findings = [f async for f in adapter.parse_output(raw_json, target)]
    assert len(findings) == 1
    assert findings[0].pik["url"] == "https://example.com/dashboard"
    assert findings[0].data["status_code"] == 200


@pytest.mark.asyncio
async def test_arjun_parser():
    adapter = ArjunAdapter()
    target = WebEndpoint.create(url="https://example.com/search")

    raw_text = "[+] Valid parameter found: query (GET)\n[+] Valid parameter found: page (GET)\n"
    findings = [f async for f in adapter.parse_output(raw_text, target)]
    assert len(findings) == 2
    assert findings[0].schema_type == "web.parameter"
    assert findings[0].pik["param_name"] == "query"
    assert findings[1].pik["param_name"] == "page"
