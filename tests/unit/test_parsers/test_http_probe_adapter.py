"""Unit tests for the http_probe native adapter and SSRF defense."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.schemas.web import WebEndpoint
from tools.http_probe.adapter import HTTPProbeAdapter


@pytest.fixture
def adapter():
    return HTTPProbeAdapter()


def test_http_probe_tier(adapter):
    assert adapter.execution_tier == "coroutine"
    assert adapter.validate_install() is True


@pytest.mark.asyncio
async def test_http_probe_ssrf_blocked_metadata(adapter):
    """Verify that cloud metadata targets raise PolicyViolationError under safe policy."""
    spooled = []

    async def fake_spool(line, is_error=False):
        spooled.append(line)

    ctx = ExecutionContext(action_id="act-test", session_id="sess-test", spool_fn=fake_spool)
    target = WebEndpoint.create(url="http://169.254.169.254/latest/meta-data")

    with pytest.raises(PolicyViolationError, match="blocked by SSRF policy"):
        async for _ in adapter.execute_action(target, {"policy": "safe"}, ctx):
            pass

    assert any("SSRF Defense Triggered" in l for l in spooled)


@pytest.mark.asyncio
async def test_http_probe_ssrf_blocked_loopback(adapter):
    """Verify that loopback targets raise PolicyViolationError under safe policy."""
    spooled = []

    async def fake_spool(line, is_error=False):
        spooled.append(line)

    ctx = ExecutionContext(action_id="act-test", session_id="sess-test", spool_fn=fake_spool)
    target = WebEndpoint.create(url="http://127.0.0.1:8080/admin")

    with pytest.raises(PolicyViolationError, match="blocked by SSRF policy"):
        async for _ in adapter.execute_action(target, {"policy": "safe"}, ctx):
            pass


@pytest.mark.asyncio
async def test_http_probe_ssrf_bypassed_in_unrestricted(adapter):
    """Verify that under unrestricted policy, SSRF check does not abort execution."""
    spooled = []

    async def fake_spool(line, is_error=False):
        spooled.append(line)

    ctx = ExecutionContext(action_id="act-test", session_id="sess-test", spool_fn=fake_spool)
    target = WebEndpoint.create(url="http://127.0.0.1:8080/status")

    mock_resp = httpx.Response(
        status_code=200,
        headers={"Server": "nginx/1.24", "X-Powered-By": "Express"},
        text="<html><head><title>Admin Panel</title></head><body>OK</body></html>",
        request=httpx.Request("GET", "http://127.0.0.1:8080/status"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        findings = [
            f async for f in adapter.execute_action(target, {"policy": "unrestricted"}, ctx)
        ]

    types = [f.schema_type for f in findings]
    assert "network.service" in types
    assert "web.endpoint" in types
    assert "web.technology" in types


@pytest.mark.asyncio
async def test_http_probe_execute_action_success(adapter):
    """Verify standard HTTP probing, spooling, and finding emission."""
    spooled = []

    async def fake_spool(line, is_error=False):
        spooled.append(line)

    ctx = ExecutionContext(action_id="act-test-http", session_id="sess-test", spool_fn=fake_spool)
    target = WebEndpoint.create(url="http://example.com/", host_ip="93.184.216.34", port=80)

    mock_resp = httpx.Response(
        status_code=200,
        headers={"Server": "Apache/2.4.52", "Content-Type": "text/html"},
        text="<html><head><title>Example Domain</title></head><body><h1>Example Domain</h1></body></html>",
        request=httpx.Request("GET", "http://example.com/"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        findings = [
            f async for f in adapter.execute_action(target, {"policy": "unrestricted"}, ctx)
        ]

    assert len(findings) >= 3  # NetworkHost, NetworkService, WebEndpoint, WebTechnology
    host = next(f for f in findings if f.schema_type == "network.host")
    assert host.pik["ip"] == "93.184.216.34"

    endpoint = next(f for f in findings if f.schema_type == "web.endpoint")
    assert endpoint.data["url"] == "http://example.com/"
    assert endpoint.data["status_code"] == 200
    assert endpoint.data["title"] == "Example Domain"

    service = next(f for f in findings if f.schema_type == "network.service")
    assert service.data["port"] == 80
    assert service.data["banner"].lower() == "apache/2.4.52"

    tech = next(f for f in findings if f.schema_type == "web.technology")
    assert tech.data["technology_name"].lower() == "apache/2.4.52"

    assert any("HTTP 200" in l for l in spooled)
    assert any("Page Title: Example Domain" in l for l in spooled)


@pytest.mark.asyncio
async def test_http_probe_tls_fingerprint_and_favicon_anchoring(adapter):
    """Verify that TLS peer cert fingerprint and favicon hash are extracted and set as anchors."""
    spooled = []

    async def fake_spool(line, is_error=False):
        spooled.append(line)

    ctx = ExecutionContext(action_id="act-test-tls", session_id="sess-test", spool_fn=fake_spool)
    target = WebEndpoint.create(
        url="https://secure.example.com/", host_ip="93.184.216.34", port=443
    )

    mock_resp = httpx.Response(
        status_code=200,
        headers={"Server": "nginx/1.24"},
        text="<html><head><title>Secure Portal</title></head><body>Secure</body></html>",
        request=httpx.Request("GET", "https://secure.example.com/"),
    )
    mock_fav = httpx.Response(
        status_code=200,
        content=b"\x00\x00\x01\x00favicon-bytes-test",
        request=httpx.Request("GET", "https://secure.example.com/favicon.ico"),
    )

    async def mock_get(url_arg, **kwargs):
        if "favicon.ico" in str(url_arg):
            return mock_fav
        return mock_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        findings = [
            f
            async for f in adapter.execute_action(
                target,
                {"policy": "unrestricted", "tls_fingerprint": "abcd1234ef567890"},
                ctx,
            )
        ]

    # Verify NetworkService
    svc = next(f for f in findings if f.schema_type == "network.service")
    assert svc.anchor_hash == "tls:abcd1234ef567890"
    assert svc.data["tls_cert_sha256"] == "abcd1234ef567890"

    # Verify TLSCertificate
    tls_cert = next(f for f in findings if f.schema_type == "tls.certificate")
    assert tls_cert.anchor_hash == "tls:abcd1234ef567890"
    assert tls_cert.data["fingerprint"] == "abcd1234ef567890"

    # Verify WebEndpoint
    endpoint = next(f for f in findings if f.schema_type == "web.endpoint")
    assert endpoint.anchor_hash == "tls:abcd1234ef567890"
    assert "favicon_hash" in endpoint.data
