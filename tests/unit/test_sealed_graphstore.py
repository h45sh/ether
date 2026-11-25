"""Unit tests for Sealed GraphStore, WriteQueueWorker, Forensic Sealing, and Scoped VectorIndex."""

import pytest

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.asyncio
@pytest.mark.fast
async def test_list_all_sessions_across_workspaces():
    """Verify list_all_sessions returns sessions across all workspaces with optional status filter."""
    store = GraphStore(":memory:")
    await store.initialize()

    ws1 = await store.create_workspace("WS1")
    ws2 = await store.create_workspace("WS2")
    s1 = await store.create_session(ws1, "Sess1")
    s2 = await store.create_session(ws2, "Sess2")
    await store.close_session(s2)

    all_sessions = await store.list_all_sessions()
    ids = {s["id"] for s in all_sessions}
    assert {s1, s2}.issubset(ids)

    active_sessions = await store.list_all_sessions(status_filter="ACTIVE")
    assert s1 in {s["id"] for s in active_sessions}
    assert s2 not in {s["id"] for s in active_sessions}

    closed_sessions = await store.list_all_sessions(status_filter="CLOSED")
    assert s2 in {s["id"] for s in closed_sessions}
    assert s1 not in {s["id"] for s in closed_sessions}

    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_upsert_node_beliefs_batch():
    """Verify upsert_node_beliefs_batch persists multiple node beliefs atomically."""
    store = GraphStore(":memory:")
    await store.initialize()
    _, sess_id = await store.get_or_create_default_session()

    n1 = await store.upsert_finding(sess_id, NetworkHost.create(ip="10.0.0.1"))
    n2 = await store.upsert_finding(sess_id, NetworkHost.create(ip="10.0.0.2"))

    await store.upsert_node_beliefs_batch(
        sess_id,
        [
            {
                "node_id": n1,
                "confidence": 0.4,
                "is_honeypot": 1,
                "is_tarpit": 0,
                "indicators": ["canary_port"],
            },
            {
                "node_id": n2,
                "confidence": 0.95,
                "is_honeypot": 0,
                "is_tarpit": 0,
                "indicators": [],
            },
        ],
    )

    b1 = await store.get_node_belief(sess_id, n1)
    assert b1 is not None
    assert b1["confidence"] == 0.4
    assert b1["is_honeypot"] is True
    assert b1["indicators"] == ["canary_port"]

    beliefs = await store.list_node_beliefs(sess_id)
    assert len(beliefs) == 2

    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_hydrated_pik_and_data_on_node_queries():
    """Verify query, get_all_nodes, get_node, and get_workspace_nodes hydrate pik and data dicts."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    svc = NetworkService.create(
        host_ip="10.1.2.3",
        port=8080,
        protocol="tcp",
        service_name="http-alt",
        banner="Jetty",
    )
    svc_id = await store.upsert_finding(sess_id, svc)

    # 1. query()
    q_rows = await store.query("network.service", session_id=sess_id)
    assert len(q_rows) == 1
    assert q_rows[0]["pik"] == {"host_ip": "10.1.2.3", "port": 8080, "protocol": "tcp"}
    assert q_rows[0]["data"]["service_name"] == "http-alt"
    assert "pik_json" in q_rows[0] and "data_json" in q_rows[0]

    # 2. get_all_nodes()
    all_rows = await store.get_all_nodes(sess_id, schema_type="network.service")
    assert all_rows[0]["pik"]["port"] == 8080
    assert all_rows[0]["data"]["banner"] == "Jetty"

    # 3. get_node()
    node = await store.get_node(sess_id, svc_id)
    assert node is not None
    assert node["pik"]["host_ip"] == "10.1.2.3"
    assert node["data"]["service_name"] == "http-alt"

    # 4. get_workspace_nodes()
    ws_rows = await store.get_workspace_nodes(ws_id)
    svc_ws = [r for r in ws_rows if r["id"] == svc_id][0]
    assert svc_ws["pik"]["port"] == 8080
    assert svc_ws["data"]["service_name"] == "http-alt"

    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_graphstore_no_public_connection_method():
    """Verify GraphStore.connection() is removed from the public interface."""
    assert not hasattr(GraphStore, "connection")
    store = GraphStore(":memory:")
    await store.initialize()
    assert not hasattr(store, "connection")
    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_forensic_sealing_blocks_all_session_mutators():
    """Verify CLOSED sessions reject all mutators with PermissionError via centralized sealing."""
    from ether.schemas.power import ActionRequest

    store = GraphStore(":memory:")
    await store.initialize()
    ws_id = await store.create_workspace("SealWS")
    sess_id = await store.create_session(ws_id, "SealSess")

    host_id = await store.upsert_finding(sess_id, NetworkHost.create(ip="10.20.30.40"))
    action = ActionRequest(
        session_id=sess_id, tool_name="nmap", target_entity_id="10.20.30.40"
    )
    await store.append_event(sess_id, action, {"ok": True}, "scan done")
    await store.save_notes("session", sess_id, "initial note")

    # Seal the session
    await store.close_session(sess_id)
    assert await store.is_session_closed(sess_id) is True

    mutator_calls = [
        store.upsert_finding(sess_id, NetworkHost.create(ip="10.20.30.41")),
        store.upsert_findings_batch(sess_id, [NetworkHost.create(ip="10.20.30.42")]),
        store.update_node_data(sess_id, host_id, {"alias": "tamper"}),
        store.reconcile_state_decay(sess_id),
        store.prune_stale_nodes(sess_id, max_age_seconds=0),
        store.upsert_node_belief(host_id, sess_id, confidence=0.1),
        store.upsert_node_beliefs_batch(sess_id, [{"node_id": host_id, "confidence": 0.1}]),
        store.append_event(sess_id, action, {}, "tamper event"),
        store.timeline.mark_event_closed(action.action_id, sess_id),
        store.timeline.compact_timeline(sess_id, keep_closed_events=0),
        store.save_notes("session", sess_id, "tampered note"),
        store.save_notes("learning", sess_id, "tampered learning"),
        store.rename_session(sess_id, "TamperedName"),
    ]

    for coro in mutator_calls:
        with pytest.raises(PermissionError, match="forensically sealed"):
            await coro

    # Reopen should still work and restore mutability
    await store.reopen_session(sess_id)
    await store.update_node_data(sess_id, host_id, {"alias": "legit"})
    node = await store.get_node(sess_id, host_id)
    assert node is not None
    assert node["data"]["alias"] == "legit"

    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_vec_findings_session_partitioned_search():
    """Verify vec_findings KNN queries are partitioned by session_id and never truncated by other sessions."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id = await store.create_workspace("VecWS")
    s1 = await store.create_session(ws_id, "NoisySession")
    s2 = await store.create_session(ws_id, "TargetSession")

    # Populate s1 with 110 services matching "Apache HTTP" (exceeding old global k=100)
    s1_findings = [
        NetworkService.create(
            host_ip=f"10.0.{i // 250}.{(i % 250) + 1}",
            port=8000 + i,
            protocol="tcp",
            service_name="http",
            banner="Apache HTTP Server 2.4.50",
        )
        for i in range(110)
    ]
    await store.upsert_findings_batch(s1, s1_findings)

    # Populate s2 with 1 matching service
    target_svc = NetworkService.create(
        host_ip="192.168.50.10",
        port=443,
        protocol="tcp",
        service_name="https",
        banner="Apache HTTP Server 2.4.50",
    )
    target_id = await store.upsert_finding(s2, target_svc)

    results = await store.semantic_search(s2, "Apache HTTP Server", limit=5)
    assert any(r["id"] == target_id for r in results)
    assert all(r["session_id"] == s2 for r in results)

    await store.close()
