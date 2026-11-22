"""Unit tests for GraphStore vector indexing, semantic search, and lifecycle management."""

import pytest

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService
from ether.schemas.vulnerability import VulnerabilityFound
from ether.schemas.web import WebEndpoint, WebTechnology


@pytest.mark.asyncio
@pytest.mark.fast
async def test_vector_indexing_and_semantic_search():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()

    # Create diverse findings
    f1 = NetworkService.create(
        host_ip="10.0.0.1", port=80, protocol="tcp", service_name="http", banner="nginx/1.18.0 (Ubuntu)"
    )
    f2 = NetworkService.create(
        host_ip="10.0.0.1", port=22, protocol="tcp", service_name="ssh", banner="OpenSSH 8.2p1 Ubuntu"
    )
    f3 = VulnerabilityFound.create(
        host_ip="10.0.0.1",
        vuln_id="CVE-2021-44228",
        port=8080,
        severity="CRITICAL",
        title="Apache Log4j Remote Code Execution",
        description="Log4Shell JNDI injection vulnerability allows remote unauthenticated code execution",
    )
    f4 = WebTechnology.create(
        url="http://10.0.0.1:80",
        technology_name="WordPress",
        version="6.2",
        categories=["CMS", "Blogs"],
    )

    node_ids = await store.upsert_findings_batch(sess_id, [f1, f2, f3, f4])
    assert len(node_ids) == 4

    # 1. Semantic search for nginx
    results_nginx = await store.semantic_search(sess_id, "nginx reverse proxy web server", limit=5)
    assert len(results_nginx) >= 1
    top_match = results_nginx[0]
    assert top_match["schema_type"] == "network.service"
    assert "nginx" in top_match["data_json"].lower()
    assert top_match["similarity"] > 0.0

    # 2. Semantic search for log4shell vulnerability
    results_vuln = await store.semantic_search(sess_id, "Log4Shell remote code execution CVE-2021-44228", limit=5)
    assert len(results_vuln) >= 1
    assert results_vuln[0]["schema_type"] == "vulnerability.found"
    assert "cve-2021-44228" in results_vuln[0]["data_json"].lower()

    # 3. Schema type filtering
    results_filtered = await store.semantic_search(
        sess_id, "web server nginx", schema_type="web.technology", limit=5
    )
    for r in results_filtered:
        assert r["schema_type"] == "web.technology"

    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_vector_session_isolation():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_a = await store.get_or_create_default_session()
    sess_b = await store.create_session(ws_id, "Session B")

    f_a = NetworkHost.create(ip="192.168.1.10", os="Linux Ubuntu")
    f_b = NetworkHost.create(ip="10.10.10.20", os="Windows Server 2022")

    await store.upsert_finding(sess_a, f_a)
    await store.upsert_finding(sess_b, f_b)

    # Search in sess_a should only find 192.168.1.10
    res_a = await store.semantic_search(sess_a, "Windows Server", limit=5)
    assert len(res_a) == 0 or all(r["session_id"] == sess_a for r in res_a)

    res_b = await store.semantic_search(sess_b, "Windows Server", limit=5)
    assert len(res_b) >= 1
    assert res_b[0]["session_id"] == sess_b

    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_vector_stale_and_pruning_lifecycle():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()

    f = WebEndpoint.create(url="http://test.local/temp", status_code=200, title="Temporary")
    nid = await store.upsert_finding(sess_id, f)

    # Verify searchable
    res = await store.semantic_search(sess_id, "temporary web endpoint")
    assert len(res) == 1

    # Mark stale
    async with store._get_conn() as db:
        await db.execute("UPDATE nodes SET status = 'stale', last_seen_at = '2020-01-01 00:00:00' WHERE id = ?", (nid,))
        await db.commit()

    # Search with default (stale excluded)
    res_active = await store.semantic_search(sess_id, "temporary web endpoint", include_stale=False)
    assert len(res_active) == 0

    # Search with include_stale=True
    res_stale = await store.semantic_search(sess_id, "temporary web endpoint", include_stale=True)
    assert len(res_stale) == 1

    # Prune stale nodes
    pruned = await store.prune_stale_nodes(sess_id, max_age_seconds=100)
    assert pruned == 1

    # Verify deleted from vec_findings
    async with store._get_conn() as db:
        cur = await db.execute("SELECT count(*) FROM vec_findings WHERE node_id = ?", (nid,))
        row = await cur.fetchone()
        assert row[0] == 0

    await store.close()
