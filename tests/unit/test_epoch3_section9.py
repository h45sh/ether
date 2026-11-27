"""Unit tests for Epoch 3 Section 9 (ADR 0019): bundled lockfile, tls_probe, http_probe, nmap."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.gateway.flags import FlagFirewall
from ether.gateway.gate import GatePolicy
from ether.registry.loader import PluginLoader, PluginSecurityError, PluginTrustMode
from ether.registry.registry import ToolRegistry
from ether.schemas.network import NetworkHost, NetworkService
from tools.http_probe.adapter import HTTPProbeAdapter
from tools.nmap.adapter import NmapAdapter, _should_use_two_stage
from tools.tls_probe.adapter import TlsProbeAdapter


@pytest.mark.fast
def test_plugin_loader_strict_rejects_unverified_external_and_tampered_bundled(
    tmp_path: Path, monkeypatch
):
    """External plugins still require .toml.sha256 + .py.sig; tampered bundled locks fail closed."""
    ext_dir = tmp_path / "external_tool"
    ext_dir.mkdir()
    (ext_dir / "manifest.toml").write_text('[meta]\nname = "ext"\n', encoding="utf-8")
    (ext_dir / "adapter.py").write_text(
        "from ether.registry.adapter import ToolAdapter\nclass Ext(ToolAdapter):\n    pass\n",
        encoding="utf-8",
    )

    loader = PluginLoader(trust_mode=PluginTrustMode.STRICT)
    with pytest.raises(PluginSecurityError):
        loader.load_verified_adapter(ext_dir / "adapter.py", ext_dir / "manifest.toml")

    # Simulate bundled adapter tampering by pointing _find_bundled_tools_root at a copy with stale lock
    fake_tools = tmp_path / "tools"
    fake_tls = fake_tools / "tls_probe"
    fake_tls.mkdir(parents=True)
    (fake_tls / "manifest.toml").write_text('[meta]\nname = "tls_probe"\n', encoding="utf-8")
    (fake_tls / "adapter.py").write_text(
        "from ether.registry.adapter import ToolAdapter\nclass T(ToolAdapter):\n    pass\n",
        encoding="utf-8",
    )
    (fake_tools / "bundle_lock.json").write_text(
        '{"version": 1, "adapters": {"tls_probe": {"manifest_sha256": "deadbeef", "adapter_sha256": "deadbeef"}}}',
        encoding="utf-8",
    )
    monkeypatch.setattr("ether.registry.loader._find_bundled_tools_root", lambda: fake_tools)
    with pytest.raises(PluginSecurityError, match="SHA-256 mismatch"):
        loader.load_verified_adapter(fake_tls / "adapter.py", fake_tls / "manifest.toml")


@pytest.mark.fast
def test_tls_probe_port_resolution_and_flag_firewall():
    """TlsProbeAdapter resolves port precedence cleanly and FlagFirewall permits -p/--port."""
    adapter = TlsProbeAdapter()
    target_host = NetworkHost.create(ip="10.48.157.67")
    assert adapter._resolve_target_host_port(target_host, {"flags": "-p 8443"}) == (
        "10.48.157.67",
        8443,
    )
    assert adapter._resolve_target_host_port(target_host, {"flags": "--port=8443"}) == (
        "10.48.157.67",
        8443,
    )
    assert adapter._resolve_target_host_port(target_host, {"flags": "-p8443"}) == (
        "10.48.157.67",
        8443,
    )
    assert adapter._resolve_target_host_port(target_host, {"port": 9443}) == (
        "10.48.157.67",
        9443,
    )
    assert adapter._resolve_target_host_port(target_host, {}) == ("10.48.157.67", 443)

    target_svc = NetworkService.create(
        host_ip="10.48.157.67", port=443, protocol="tcp", service_name="https"
    )
    assert adapter._resolve_target_host_port(target_svc, {"flags": "-p 8443"}) == (
        "10.48.157.67",
        8443,
    )

    with pytest.raises(ValueError):
        adapter._resolve_target_host_port(target_host, {"flags": "-p 99999"})

    reg = ToolRegistry(tools_dir=Path("tools"))
    fw = FlagFirewall(registry=reg)
    assert fw.validate_arguments("tls_probe", "-p 8443", GatePolicy.SAFE) == ["-p", "8443"]


@pytest.mark.fast
@pytest.mark.asyncio
async def test_http_probe_policy_gated_tls_override():
    """HTTPProbeAdapter rejects -k/verify_tls=False in SAFE mode and honors it in UNRESTRICTED."""
    adapter = HTTPProbeAdapter()
    target = NetworkHost.create(ip="1.1.1.1")

    safe_ctx = ExecutionContext(action_id="a1", session_id="s1", policy="safe")
    with patch("tools.http_probe.adapter.ScopeValidator.check_destination") as mock_scope:
        mock_scope.return_value = SimpleNamespace(allowed=True, reason="ok")
        with pytest.raises(PolicyViolationError):
            async for _ in adapter.execute_action(target, {"flags": "-k"}, safe_ctx):
                pass
        with pytest.raises(PolicyViolationError):
            async for _ in adapter.execute_action(target, {"verify_tls": False}, safe_ctx):
                pass

    unrestricted_ctx = ExecutionContext(action_id="a2", session_id="s1", policy="unrestricted")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.reason_phrase = "OK"
    mock_resp.headers = {"server": "test"}
    mock_resp.text = "<title>Lab</title>"
    mock_resp.history = []
    mock_resp.url = "https://1.1.1.1:8443/"

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(
        side_effect=[mock_resp, SimpleNamespace(status_code=404, content=b"")]
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("tools.http_probe.adapter.ScopeValidator.check_destination") as mock_scope,
        patch(
            "ether.common.transport.PinnedTransport.create_client", return_value=mock_client
        ) as mock_pt,
    ):
        mock_scope.return_value = SimpleNamespace(allowed=True, reason="ok")
        findings = [
            f
            async for f in adapter.execute_action(
                target,
                {"url": "https://1.1.1.1:8443/", "flags": "-k", "tls_cert_sha256": "abc"},
                unrestricted_ctx,
            )
        ]

    assert mock_pt.call_args.kwargs["verify_tls"] is False
    endpoints = [f for f in findings if f.schema_type == "web.endpoint"]
    assert len(endpoints) == 1
    assert endpoints[0].data["tls_verified"] is False


@pytest.mark.fast
@pytest.mark.asyncio
async def test_nmap_two_stage_adaptive_and_timeout_salvage():
    """NmapAdapter splits broad -sV scans, skips Stage 2 on 0 ports, and salvages on timeout."""
    assert _should_use_two_stage(["-sV", "--top-ports", "1000", "-Pn"]) is True
    assert _should_use_two_stage(["-sV"]) is True
    assert _should_use_two_stage(["-sV", "-p", "80,443"]) is False
    assert _should_use_two_stage(["-sT", "--top-ports", "1000"]) is False

    adapter = NmapAdapter()
    target = NetworkHost.create(ip="10.0.0.5")

    # 1. Broad -sV -> Stage 1 finds port 80 -> Stage 2 runs with -sV -p 80
    calls: list[list[str]] = []

    class _FakeRunner:
        def __init__(self, mode: str) -> None:
            self.mode = mode

        async def run(self, *, params, on_output, timeout_seconds, **kwargs):
            flags = list(params.get("flags", []))
            calls.append(flags)
            if self.mode == "two_stage":
                if "-sV" not in flags:
                    yield NetworkService.create(
                        host_ip="10.0.0.5", port=80, protocol="tcp", service_name="http"
                    )
                else:
                    yield NetworkService.create(
                        host_ip="10.0.0.5",
                        port=80,
                        protocol="tcp",
                        service_name="http",
                        banner="nginx 1.24",
                    )
            elif self.mode == "zero_ports":
                return
                yield
            elif self.mode == "s1_timeout":
                await on_output(
                    '<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/></port>'
                )
                raise TimeoutError("Stage 1 timed out")

    ctx = ExecutionContext(
        action_id="nmap1",
        session_id="s1",
        runner=_FakeRunner("two_stage"),
        timeout_seconds=100,
    )
    findings = [
        f async for f in adapter.execute_action(target, {"flags": "-sV --top-ports 1000 -Pn"}, ctx)
    ]
    assert len(calls) == 2
    assert "-sV" not in calls[0]
    assert "-sV" in calls[1] and "-p" in calls[1] and "80" in calls[1]
    assert any(f.data.get("banner") == "nginx 1.24" for f in findings)

    # 2. Zero open ports -> Stage 2 skipped
    calls.clear()
    ctx_zero = ExecutionContext(
        action_id="nmap2",
        session_id="s1",
        runner=_FakeRunner("zero_ports"),
        timeout_seconds=100,
    )
    findings_zero = [
        f async for f in adapter.execute_action(target, {"flags": "-sV -Pn"}, ctx_zero)
    ]
    assert len(calls) == 1
    assert findings_zero == []

    # 3. Stage 1 timeout -> salvages partial XML and stops without Stage 2
    calls.clear()
    ctx_t1 = ExecutionContext(
        action_id="nmap3",
        session_id="s1",
        runner=_FakeRunner("s1_timeout"),
        timeout_seconds=100,
    )
    findings_t1 = [f async for f in adapter.execute_action(target, {"flags": "-sV -Pn"}, ctx_t1)]
    assert len(calls) == 1
    assert any(f.pik.get("port") == 22 for f in findings_t1)
