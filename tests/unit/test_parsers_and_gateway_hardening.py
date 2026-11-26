"""Unit tests for Gobuster linear parser, flag smuggling firewall, IP:PORT target inference, and HTTP probe previews."""

import pytest

from ether.common.context import ExecutionContext
from ether.common.scope import EngagementScope
from ether.gateway.gate import ActionGateway, ActionValidationError, GatePolicy
from ether.gateway.preflight import PreflightVerifier
from ether.registry.target_inference import infer_target_finding
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkService
from ether.schemas.power import ActionRequest
from tools.gobuster.adapter import GobusterAdapter
from tools.imds_probe.adapter import ImdsProbeAdapter


@pytest.mark.asyncio
async def test_gobuster_linear_parser_redos_immunity():
    adapter = GobusterAdapter()
    target = BaseFinding(schema_type="web.endpoint", pik={"url": "http://example.com"}, data={})

    # Hostile 100,000-character line with no whitespace or spaces
    hostile_line = "A" * 100000
    valid_line = "/admin (Status: 200) [Size: 1234]"
    raw_stdout = f"{hostile_line}\n{valid_line}\n"

    findings = [f async for f in adapter.parse_output(raw_stdout, target)]
    assert len(findings) == 1
    assert findings[0].pik["url"] == "http://example.com/admin"
    assert findings[0].data["status_code"] == 200


def test_target_inference_ip_port():
    target = "127.0.0.1:34291"
    finding = infer_target_finding(target)
    assert isinstance(finding, NetworkService)
    assert finding.schema_type == "network.service"
    assert finding.pik["host_ip"] == "127.0.0.1"
    assert finding.pik["port"] == 34291


def test_preflight_flag_smuggling_and_metachars():
    verifier = PreflightVerifier(
        policy=GatePolicy.SAFE, scope=EngagementScope(allow_loopback=False)
    )

    # Smuggled loopback in joined flag
    r1 = verifier.verify("nmap", "scanme.nmap.org", flags="-uhttp://127.0.0.1")
    assert not r1.is_valid
    assert any("Command flags contain prohibited destination" in issue.title for issue in r1.issues)

    # Smuggled metadata in colon flag
    r2 = verifier.verify("curl", "scanme.nmap.org", flags="--resolve=meta:80:169.254.169.254")
    assert not r2.is_valid
    assert any("Command flags contain prohibited destination" in issue.title for issue in r2.issues)

    # Shell metacharacter injection
    r3 = verifier.verify("nmap", "scanme.nmap.org", flags="--tags cve; cat /etc/passwd")
    assert not r3.is_valid
    assert any("Shell metacharacters prohibited in flags" in issue.title for issue in r3.issues)


@pytest.mark.asyncio
async def test_action_gateway_flag_smuggling_rejection():
    from uuid import uuid4

    from ether.registry.registry import ToolRegistry

    gateway = ActionGateway(
        registry=ToolRegistry(), policy=GatePolicy.SAFE, scope=EngagementScope(allow_loopback=False)
    )
    action = ActionRequest(
        session_id=uuid4(),
        tool_name="nmap",
        params={"raw_flags": "--target=169.254.169.254"},
    )
    with pytest.raises(ActionValidationError):
        await gateway.validate_action(action)

    action_metachar = ActionRequest(
        session_id=uuid4(),
        tool_name="nmap",
        params={"raw_flags": "-p 80 | cat"},
    )
    with pytest.raises(ActionValidationError):
        await gateway.validate_action(action_metachar)


@pytest.mark.asyncio
async def test_imds_probe_open_redirect():
    adapter = ImdsProbeAdapter()
    target = BaseFinding(
        schema_type="web.endpoint",
        pik={"url": "http://127.0.0.1/redirect-imds"},
        data={"url": "http://127.0.0.1/redirect-imds"},
    )
    ctx = ExecutionContext(action_id="test", session_id="test", policy="unrestricted")

    # Mock response redirecting to 169.254.169.254
    from unittest.mock import AsyncMock, patch

    import httpx

    mock_resp = httpx.Response(
        status_code=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        request=httpx.Request("GET", "http://127.0.0.1/redirect-imds"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = [f async for f in adapter.execute_action(target, {}, ctx)]
        assert any(f.pik.get("resource_id") == "open-redirect-to-imds" for f in findings)
