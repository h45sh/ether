"""Unit tests for Ether Native Model Context Protocol (MCP) Server."""

import json

import pytest

from ether.graph.store import GraphStore
from ether.mcp.server import create_mcp_server
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.asyncio
async def test_mcp_server_creation_and_tool_listing():
    """Verify that MCP server registers canonical tools."""
    store = GraphStore(":memory:")
    await store.initialize()

    server = create_mcp_server(store)
    tools = await server.list_tools()
    tool_names = {t.name for t in tools}

    assert "query_graph" in tool_names
    assert "inspect_entity" in tool_names
    assert "get_diff" in tool_names

    await store.close()


@pytest.mark.asyncio
async def test_mcp_query_graph_and_inspect_entity():
    """Verify query_graph and inspect_entity read tools through MCP."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id = await store.create_workspace("McpWS")
    sess_id = await store.create_session(ws_id, "McpSess")

    host = NetworkHost.create(ip="10.10.10.5", hostname="target.lan")
    await store.upsert_finding(sess_id, host, action_id="act-init")

    service = NetworkService.create(host_ip="10.10.10.5", port=80, service_name="http")
    service_id = await store.upsert_finding(sess_id, service, action_id="act-init")

    server = create_mcp_server(store, default_session_id=sess_id)

    # 1. query_graph
    res_query = await server.call_tool("query_graph", {"schema_type": "network.service"})
    assert res_query.is_error is False
    data_query = json.loads(res_query.content[0].text)
    assert data_query["total"] >= 1
    assert any(n["id"] == service_id for n in data_query["nodes"])

    # 2. inspect_entity
    res_inspect = await server.call_tool("inspect_entity", {"entity_id": service_id})
    assert res_inspect.is_error is False
    data_inspect = json.loads(res_inspect.content[0].text)
    assert data_inspect["entity"]["id"] == service_id
    assert data_inspect["entity"]["pik"]["port"] == 80
    assert len(data_inspect["edges"]) >= 1

    await store.close()


@pytest.mark.asyncio
async def test_mcp_get_diff_by_action_id():
    """Verify get_diff MCP tool returns action delta envelope."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id = await store.create_workspace("DiffMcpWS")
    sess_id = await store.create_session(ws_id, "DiffMcpSess")

    service = NetworkService.create(host_ip="10.20.30.40", port=443, service_name="https")
    await store.upsert_finding(sess_id, service, action_id="act-scan-99")

    server = create_mcp_server(store, default_session_id=sess_id)
    res_diff = await server.call_tool("get_diff", {"action_id": "act-scan-99"})

    assert res_diff.is_error is False
    diff = json.loads(res_diff.content[0].text)
    assert diff["action_id"] == "act-scan-99"
    assert diff["tokens_consumed"] == 0
    assert len(diff["added_nodes"]) >= 1

    await store.close()
