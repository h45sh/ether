"""Unit tests for EtherSettings, lazy ToolRegistry, profile execution, and MCP RBAC."""

import pytest

from ether.config import EtherSettings
from ether.mcp.security import (
    _CURRENT_AUTH_CONTEXT,
    AuthContext,
    AuthError,
    OperationType,
    require_operation,
)
from ether.registry.registry import ToolRegistry


@pytest.mark.fast
def test_ether_settings_precedence(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        '[execution]\ndefault_timeout_sec = 45.0\n[gateway]\npolicy = "unrestricted"\n',
        encoding="utf-8",
    )
    env = {
        "ETHER_EXECUTION__DEFAULT_TIMEOUT_SEC": "90.0",
        "ETHER_DEBUG": "true",
        "ETHER_PLUGIN_TRUST_MODE": "strict",
    }
    settings = EtherSettings.load(
        data_dir=str(tmp_path),
        config_path=cfg_file,
        cli_overrides={"gateway": {"policy": "safe"}},
        env=env,
    )
    assert settings.gateway.policy == "safe"  # CLI overrides config.toml
    assert settings.execution.default_timeout_sec == 90.0  # env overrides config.toml
    assert settings.logging.debug is True
    assert settings.registry.trust_mode == "strict"


@pytest.mark.fast
def test_lazy_tool_registry_and_search():
    settings = EtherSettings()
    reg = ToolRegistry(settings=settings)
    reg.load_tools()

    assert len(reg.tools) >= 30
    # Adapters are not imported until get_tool() is called
    assert not reg.is_adapter_loaded("nmap")

    matches = reg.search_tools(query="nmap", produces="network.service")
    assert any(m["name"] == "nmap" and "fast" in m["profiles"] for m in matches)
    assert not reg.is_adapter_loaded("nmap")  # search does not import adapter

    loaded = reg.get_tool("nmap")
    assert loaded is not None and loaded["adapter"] is not None
    assert reg.is_adapter_loaded("nmap")


@pytest.mark.fast
def test_mcp_per_tool_rbac_enforcement():
    readonly_ctx = AuthContext(subject="reader", scopes=frozenset({OperationType.GRAPH_QUERY.value}))
    tok = _CURRENT_AUTH_CONTEXT.set(readonly_ctx)
    try:
        require_operation(OperationType.GRAPH_QUERY)
        with pytest.raises(AuthError) as exc:
            require_operation(OperationType.TOOL_EXECUTE)
        assert exc.value.status_code == 403
    finally:
        _CURRENT_AUTH_CONTEXT.reset(tok)


@pytest.mark.asyncio
@pytest.mark.fast
async def test_python_sdk_ether_open_facade():
    from ether import Ether

    async with Ether.open(db_path=":memory:", policy="safe") as client:
        matches = client.search_tools(query="nmap")
        assert any(m["name"] == "nmap" for m in matches)
        snap = await client.snapshot()
        assert "nodes" in snap or "findings" in snap or isinstance(snap, dict)
