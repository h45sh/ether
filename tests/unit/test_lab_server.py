"""Unit tests for LabMockServer."""

import asyncio

import pytest

from tests.fakes.lab_server import LabMockServer


async def _async_http_get(host: str, port: int, path: str) -> tuple[int, str]:
    reader, writer = await asyncio.open_connection(host, port)
    req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    writer.write(req.encode("utf-8"))
    await writer.drain()

    response = await reader.read()
    writer.close()
    await writer.wait_closed()

    response_text = response.decode("utf-8", errors="replace")
    status_line = response_text.split("\r\n")[0]
    status_code = int(status_line.split()[1])
    return status_code, response_text


@pytest.mark.asyncio
async def test_lab_mock_server_lifecycle_and_endpoints():
    """Verify that LabMockServer boots on loopback, responds to standard endpoints, and stops cleanly."""
    port = 18888
    async with LabMockServer(host="127.0.0.1", port=port) as server:
        assert server.server is not None

        # Test GET /
        status, content = await _async_http_get("127.0.0.1", port, "/")
        assert status == 200
        assert "Ether Practice Lab Target" in content
        assert "Server: Ether-MockLab/1.0" in content

        # Test GET /robots.txt
        status, content = await _async_http_get("127.0.0.1", port, "/robots.txt")
        assert status == 200
        assert "Disallow: /admin" in content

        # Test GET /api/version
        status, content = await _async_http_get("127.0.0.1", port, "/api/version")
        assert status == 200
        assert "ether-lab-portal" in content

        # Test GET /admin -> 403
        status, content = await _async_http_get("127.0.0.1", port, "/admin")
        assert status == 403

        # Test GET /nonexistent -> 404
        status, content = await _async_http_get("127.0.0.1", port, "/nonexistent")
        assert status == 404

    # Server should be stopped after exiting context manager
    assert server.server is None
