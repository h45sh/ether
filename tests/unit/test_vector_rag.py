"""Unit tests for Agent Telemetry RAG Integration & MCP Semantic Search Tool."""

import json

import pytest

from ether.graph.store import GraphStore
from ether.graph.telemetry import GraphTelemetryCompiler
from ether.mcp.server import create_mcp_server
from ether.schemas.network import NetworkService
from ether.schemas.vulnerability import VulnerabilityFound


@pytest.mark.asyncio
@pytest.mark.fast
async def test_telemetry_compiler_rag_snapshot():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()

    f1 = NetworkService.create(
        host_ip="10.0.0.1",
        port=80,
        protocol="tcp",
        service_name="http",
        banner="Apache/2.4.49 (Unix)",
    )
    f2 = VulnerabilityFound.create(
        host_ip="10.0.0.1",
        vuln_id="CVE-2021-41773",
        port=80,
        severity="CRITICAL",
        title="Apache HTTP Server Path Traversal and RCE",
        description="A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49",
    )
    await store.upsert_findings_batch(sess_id, [f1, f2])

    compiler = GraphTelemetryCompiler(store, sess_id)

    # 1. Snapshot without objective has empty rag_findings
    snap_no_obj = await compiler.compile_telemetry_snapshot()
    assert "rag_findings" in snap_no_obj
    assert snap_no_obj["rag_findings"] == []

    # 2. Snapshot with objective retrieves relevant findings via RAG
    snap_with_obj = await compiler.compile_telemetry_snapshot(
        objective="Apache HTTP Server path traversal vulnerability"
    )
    assert len(snap_with_obj["rag_findings"]) >= 1
    top_rag = snap_with_obj["rag_findings"][0]
    assert (
        "apache" in top_rag["data_json"].lower() or "cve-2021-41773" in top_rag["data_json"].lower()
    )

    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_mcp_search_findings_semantic():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()

    f_ssh = NetworkService.create(
        host_ip="192.168.1.100", port=22, protocol="tcp", service_name="ssh", banner="OpenSSH 8.9p1"
    )
    f_vuln = VulnerabilityFound.create(
        host_ip="192.168.1.100",
        vuln_id="CVE-2023-38408",
        port=22,
        severity="HIGH",
        title="OpenSSH PKCS#11 Provider RCE",
    )
    await store.upsert_findings_batch(sess_id, [f_ssh, f_vuln])

    server = create_mcp_server(store=store, default_session_id=sess_id)

    # Check search_findings_semantic tool exists
    tool_map = {t.name: t for t in server._tool_manager.list_tools()}
    assert "search_findings_semantic" in tool_map

    # Execute tool via call_tool
    raw_res = await server.call_tool(
        "search_findings_semantic",
        arguments={
            "query": "OpenSSH remote code execution flaw",
            "session_id": sess_id,
            "limit": 5,
        },
    )
    res_text = (
        raw_res[0].text
        if isinstance(raw_res, list)
        else (raw_res.content[0].text if hasattr(raw_res, "content") else str(raw_res))
    )
    data = json.loads(res_text)

    assert data["session_id"] == sess_id
    assert data["total_matched"] >= 1
    findings = data["findings"]
    assert len(findings) >= 1
    assert "similarity" in findings[0]
    assert findings[0]["similarity"] > 0.0

    # Test schema_type filter via MCP
    filtered_res = await server.call_tool(
        "search_findings_semantic",
        arguments={
            "query": "OpenSSH",
            "session_id": sess_id,
            "schema_type": "vulnerability.found",
        },
    )
    filtered_text = (
        filtered_res[0].text
        if isinstance(filtered_res, list)
        else (
            filtered_res.content[0].text if hasattr(filtered_res, "content") else str(filtered_res)
        )
    )
    filtered_data = json.loads(filtered_text)
    for f in filtered_data["findings"]:
        assert f["schema_type"] == "vulnerability.found"

    await store.close()
