"""Integration test for stealth packet prober, deception CLI, and MCP get_deception_report."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ether.cli.commands.graph import handle_graph_belief
from ether.cli.context import CliContext
from ether.core.pipeline import PipelineParser
from ether.graph.store import GraphStore
from ether.mcp.server import create_mcp_server
from ether.registry.registry import ToolRegistry
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.asyncio
async def test_mcp_get_deception_report():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()
    host = NetworkHost.create(ip="10.10.10.10")
    host_id = await store.upsert_finding(sess_id, host)

    # Insert a honeypot banner
    svc = NetworkService.create(
        host_ip="10.10.10.10",
        port=2222,
        service_name="ssh",
        banner="SSH-2.0-Cowrie",
    )
    await store.upsert_finding(sess_id, svc)

    server = create_mcp_server(store=store)

    # Find the get_deception_report tool
    # FastMCP stores registered tools in server._tool_manager or similar
    # Call through execute tool or direct function invocation if available
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    assert "get_deception_report" in tool_names

    # Call get_deception_report tool
    result = await server.call_tool("get_deception_report", {"session_id": sess_id})
    if hasattr(result, "content") and result.content:
        content_text = result.content[0].text
    elif isinstance(result, list) and hasattr(result[0], "text"):
        content_text = result[0].text
    else:
        content_text = str(result)

    data = json.loads(content_text)
    assert data["session_id"] == sess_id
    assert len(data["flagged_honeypots"]) >= 1

    await store.close()


@pytest.mark.asyncio
async def test_cli_graph_belief():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()
    host = NetworkHost.create(ip="192.168.1.5")
    await store.upsert_finding(sess_id, host)

    args = MagicMock()
    args.session_id = sess_id
    args.evaluate = True

    context = MagicMock(spec=CliContext)
    context.is_json = True
    context.open_store.return_value.__aenter__.return_value = store

    ret = await handle_graph_belief(args, context)
    assert ret == 0

    await store.close()


def test_pipeline_parsing_with_stealth_scan():
    repo_root = Path(__file__).resolve().parent.parent.parent
    tools_dir = str(repo_root / "tools")
    registry = ToolRegistry(tools_dir)
    registry.load_tools()

    stages = PipelineParser.parse("stealth_scan(target=10.0.0.1, mode=syn) | http_probe", registry)
    assert len(stages) == 2
    assert stages[0].tool_name == "stealth_scan"
    assert stages[0].params["target"] == "10.0.0.1"
    assert stages[0].params["mode"] == "syn"
    assert stages[1].tool_name == "http_probe"
