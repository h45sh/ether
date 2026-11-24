"""Unit tests for web fuzzer 404 response geometry baseline calibration."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ether.schemas.web import WebEndpoint
from tools.ffuf.adapter import FfufAdapter, calibrate_fuzzer_baseline
from tools.gobuster.adapter import GobusterAdapter


@pytest.mark.asyncio
async def test_calibrate_fuzzer_baseline_success():
    """Verify synthetic 404 nonce probe extracts response geometry."""
    mock_response = httpx.Response(
        status_code=200,
        content=b"Custom Not Found Page Body with specific length",
        request=httpx.Request("GET", "http://target.local/.ether_probe_12345678"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await calibrate_fuzzer_baseline("http://target.local")

        assert result is not None
        assert result["status_code"] == 200
        assert result["size"] == len(b"Custom Not Found Page Body with specific length")
        assert result["words"] > 0


@pytest.mark.asyncio
async def test_calibrate_fuzzer_baseline_fail_open_timeout():
    """Verify target timeouts fail open and return None without halting workflow."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ConnectTimeout("Connection timed out")
        result = await calibrate_fuzzer_baseline("http://unreachable.local")
        assert result is None


@pytest.mark.asyncio
async def test_ffuf_adapter_injects_filter_size():
    """Verify FfufAdapter auto-synthesizes -fs flag when baseline response is calibrated."""
    adapter = FfufAdapter()
    target = WebEndpoint.create(url="http://target.local")

    with patch("tools.ffuf.adapter.calibrate_fuzzer_baseline", new_callable=AsyncMock) as mock_calib:
        mock_calib.return_value = {"status_code": 200, "size": 1337, "words": 42, "lines": 10}

        # Mock runner in context
        mock_context = AsyncMock()
        def fake_run(*args, **kwargs):
            async def _gen():
                if False:
                    yield
            return _gen()
        mock_context.runner.run = MagicMock(side_effect=fake_run)

        findings = []
        async for f in adapter.execute_action(target, {"raw_flags": "-u http://target.local/FUZZ"}, mock_context):
            findings.append(f)

        call_kwargs = mock_context.runner.run.call_args[1]
        assert "-fs 1337" in call_kwargs["params"]["raw_flags"]


@pytest.mark.asyncio
async def test_gobuster_adapter_injects_exclude_length():
    """Verify GobusterAdapter auto-synthesizes --exclude-length flag when calibrated."""
    adapter = GobusterAdapter()
    target = WebEndpoint.create(url="http://target.local")

    with patch("tools.gobuster.adapter.calibrate_fuzzer_baseline", new_callable=AsyncMock) as mock_calib:
        mock_calib.return_value = {"status_code": 200, "size": 2048, "words": 50, "lines": 12}

        mock_context = AsyncMock()
        def fake_run(*args, **kwargs):
            async def _gen():
                if False:
                    yield
            return _gen()
        mock_context.runner.run = MagicMock(side_effect=fake_run)

        findings = []
        async for f in adapter.execute_action(target, {"raw_flags": "-u http://target.local"}, mock_context):
            findings.append(f)

        call_kwargs = mock_context.runner.run.call_args[1]
        assert "--exclude-length 2048" in call_kwargs["params"]["raw_flags"]
