"""Unit tests for StealthScanAdapter and stealth packet crafting mechanics."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ether.common.context import ExecutionContext
from ether.schemas.network import NetworkHost, NetworkService
from tools.stealth_scan.adapter import StealthScanAdapter, parse_ports_spec


@pytest.fixture
def mock_context():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.spool_line = AsyncMock()
    return ctx


def test_parse_ports_spec():
    assert parse_ports_spec(None) == [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        443,
        445,
        1433,
        3306,
        3389,
        5432,
        6379,
        8080,
        8443,
    ]
    assert parse_ports_spec("80,443") == [80, 443]
    assert parse_ports_spec("21-25") == [21, 22, 23, 24, 25]
    assert parse_ports_spec([80, 8080]) == [80, 8080]


@pytest.mark.asyncio
async def test_unprivileged_fallback_open_ports(mock_context):
    adapter = StealthScanAdapter()
    target = NetworkHost.create(ip="127.0.0.1")

    # Mock asyncio.open_connection so port 80 succeeds and port 22 fails
    async def fake_open_connection(host, port):
        if port == 80:
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return MagicMock(), writer
        raise OSError("Connection refused")

    with patch("asyncio.open_connection", side_effect=fake_open_connection):
        findings = []
        async for f in adapter.execute_action(
            target,
            {"mode": "syn", "ports": "22,80", "force_unprivileged": True},
            mock_context,
        ):
            findings.append(f)

        assert len(findings) == 1
        assert isinstance(findings[0], NetworkService)
        assert findings[0].pik["port"] == 80
        assert findings[0].pik["host_ip"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_arp_mode_scope_rejection(mock_context):
    adapter = StealthScanAdapter()
    # 8.8.8.8 is public routed; ARP should be rejected
    target = NetworkHost.create(ip="8.8.8.8")

    findings = []
    async for f in adapter.execute_action(
        target,
        {"mode": "arp"},
        mock_context,
    ):
        findings.append(f)

    assert len(findings) == 0
    mock_context.spool_line.assert_called()
    assert any(
        "ARP mode rejected for routed public IP" in call.args[0]
        for call in mock_context.spool_line.call_args_list
    )


@pytest.mark.asyncio
async def test_port_knocking_execution(mock_context):
    adapter = StealthScanAdapter()
    target = NetworkHost.create(ip="127.0.0.1")

    async def fake_open_connection(host, port):
        if port == 8080:
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return MagicMock(), writer
        raise OSError("Connection refused")

    with patch("asyncio.open_connection", side_effect=fake_open_connection):
        findings = []
        async for f in adapter.execute_action(
            target,
            {
                "mode": "knock",
                "knock_sequence": "7000,8000,9000",
                "ports": "8080",
                "force_unprivileged": True,
            },
            mock_context,
        ):
            findings.append(f)

        assert len(findings) == 1
        assert findings[0].pik["port"] == 8080
