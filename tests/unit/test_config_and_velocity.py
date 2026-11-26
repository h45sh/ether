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
    settings = EtherSettings.load()
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
    readonly_ctx = AuthContext(
        subject="reader", scopes=frozenset({OperationType.GRAPH_QUERY.value})
    )
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
        nodes = await client.query(limit=10)
        assert isinstance(nodes, list)
        diff = await client.diff()
        assert "total_delta_count" in diff
        br = await client.blast_radius("nonexistent-node", max_depth=3)
        assert br["count"] == 0
        full_graph = await client.graph()
        assert "nodes" in full_graph and "edges" in full_graph


@pytest.mark.asyncio
@pytest.mark.fast
async def test_mcp_query_graph_include_edges():
    import json

    from ether.graph.store import GraphStore
    from ether.mcp.server import create_mcp_server
    from ether.schemas.network import NetworkHost, NetworkService

    store = GraphStore(":memory:")
    await store.initialize()
    ws_id = await store.create_workspace("WS")
    sess_id = await store.create_session(ws_id, "Sess")
    await store.upsert_finding(sess_id, NetworkHost.create(ip="10.0.0.1"))
    await store.upsert_finding(
        sess_id, NetworkService.create(host_ip="10.0.0.1", port=22, service_name="ssh")
    )

    server = create_mcp_server(store, default_session_id=sess_id)
    res = await server.call_tool("query_graph", {"include_edges": True})
    assert res.is_error is False
    data = json.loads(res.content[0].text)
    assert data["total"] >= 2
    assert data["total_edges"] >= 1
    assert len(data["edges"]) >= 1
    await store.close()


@pytest.mark.fast
def test_cli_ergonomic_ops_tree_session_use_and_config_init(tmp_path, capsys):
    import asyncio
    import json
    from uuid import UUID

    from ether.cli.router import main
    from ether.graph.store import GraphStore
    from ether.schemas.network import NetworkHost, NetworkService
    from ether.schemas.power import ActionRequest

    db_path = str(tmp_path / "ops.db")

    async def _seed():
        s = GraphStore(db_path)
        await s.initialize()
        ws = await s.create_workspace("OpsWS")
        sid = await s.create_session(ws, "OpsSess")
        await s.upsert_finding(sid, NetworkHost.create(ip="10.0.0.5"), action_id="act-1")
        await s.upsert_finding(
            sid,
            NetworkService.create(host_ip="10.0.0.5", port=443, service_name="https"),
            action_id="act-1",
        )
        req = ActionRequest(
            action_id=UUID("00000000-0000-0000-0000-000000000001"),
            session_id=UUID(sid),
            tool_name="nmap",
        )
        await s.timeline.append_event(sid, req, {"status": "running"}, "nmap scan")
        await s.close()
        return sid, str(req.action_id)

    sid, act_id = asyncio.run(_seed())
    base = ["--data-dir", str(tmp_path), "--db", db_path]

    assert main([*base, "--json", "session", "use", sid]) == 0
    assert json.loads(capsys.readouterr().out)["active_session"] == sid

    assert main([*base, "--json", "status"]) == 0
    st = json.loads(capsys.readouterr().out)
    assert st["session_id"] == sid and st["total_nodes"] >= 2

    assert main([*base, "graph", "tree"]) == 0
    tree_out = capsys.readouterr().out
    assert "10.0.0.5" in tree_out

    assert main([*base, "--json", "graph", "tree"]) == 0
    tree_json = json.loads(capsys.readouterr().out)
    assert tree_json["total_edges"] >= 1

    assert main([*base, "--json", "ps"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] >= 1

    assert main([*base, "--json", "kill", act_id]) == 0
    assert json.loads(capsys.readouterr().out)["aborted"] is True

    rep_file = tmp_path / "report.md"
    assert main([*base, "report", "-o", str(rep_file)]) == 0
    assert "Ether Engagement Report" in rep_file.read_text(encoding="utf-8")
    capsys.readouterr()

    assert main([*base, "--json", "config", "init"]) == 0
    assert (tmp_path / "config.toml").is_file()
    capsys.readouterr()


@pytest.mark.fast
def test_cli_config_show_and_path(tmp_path, capsys):
    import json

    from ether.cli.router import main

    rc1 = main(["--data-dir", str(tmp_path), "--json", "config", "show"])
    assert rc1 == 0
    out1 = json.loads(capsys.readouterr().out)
    assert "execution" in out1 and "gateway" in out1

    rc2 = main(["--data-dir", str(tmp_path), "config", "show"])
    assert rc2 == 0
    assert "[execution]" in capsys.readouterr().out

    rc3 = main(["--data-dir", str(tmp_path), "--json", "config", "path"])
    assert rc3 == 0
    out3 = json.loads(capsys.readouterr().out)
    assert out3["config_path"].endswith("config.toml")

    rc4 = main(["--data-dir", str(tmp_path), "config", "path"])
    assert rc4 == 0
    assert "config.toml" in capsys.readouterr().out
