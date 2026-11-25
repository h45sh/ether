import json
import os

import aiosqlite
import pytest

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.asyncio
async def test_store_initialization():
    store = GraphStore(":memory:")
    await store.initialize()

    async with store._get_conn() as db:
        # Check if tables exist
        cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in await cursor.fetchall()]
        assert "workspaces" in tables
        assert "sessions" in tables
        assert "nodes" in tables
        assert "edges" in tables
        assert "event_log" in tables
    await store.close()


@pytest.mark.asyncio
async def test_default_session_creation():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()
    assert ws_id is not None
    assert sess_id is not None

    # Run again, should return the same IDs
    ws_id2, sess_id2 = await store.get_or_create_default_session()
    assert ws_id == ws_id2
    assert sess_id == sess_id2
    await store.close()


@pytest.mark.asyncio
async def test_upsert_and_query_finding():
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    host = NetworkHost.create(ip="127.0.0.1", hostname="localhost")
    node_id = await store.upsert_finding(sess_id, host)

    results = await store.query("network.host", session_id=sess_id)
    assert len(results) == 1
    assert results[0]["id"] == node_id
    assert json.loads(results[0]["pik_json"]) == {"ip": "127.0.0.1"}
    await store.close()


@pytest.mark.asyncio
async def test_graph_wiring_parent():
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    # Upsert a service (which has a parent NetworkHost)
    service = NetworkService.create(host_ip="10.0.0.1", port=443, protocol="tcp")
    await store.upsert_finding(sess_id, service)

    # Should have created two nodes: the service AND the host
    stats = await store.get_stats(sess_id)
    assert stats["network.service"] == 1
    assert stats["network.host"] == 1

    # Should have created one edge
    async with store._get_conn() as db:
        cursor = await db.execute("SELECT count(*) FROM edges WHERE session_id = ?", (sess_id,))
        count = (await cursor.fetchone())[0]
        assert count == 1
    await store.close()


@pytest.mark.asyncio
async def test_auto_create_nonexistent_parent_dir(tmp_path):
    # Specify a path inside non-existent nested subdirectories
    nested_db = tmp_path / "deep" / "nested" / "dir" / "test.db"
    assert not nested_db.parent.exists()

    store = GraphStore(str(nested_db))
    await store.initialize()
    assert nested_db.parent.exists()
    assert nested_db.exists()
    await store.close()


@pytest.mark.asyncio
async def test_wal_mode_pragmas(tmp_path):
    db_file = tmp_path / "wal_test.db"
    store = GraphStore(str(db_file))
    await store.initialize()

    async with store._get_conn() as db:
        cursor = await db.execute("PRAGMA journal_mode")
        mode = (await cursor.fetchone())[0]
        assert mode.upper() == "WAL"

        cursor = await db.execute("PRAGMA busy_timeout")
        timeout = (await cursor.fetchone())[0]
        assert timeout == 5000

        cursor = await db.execute("PRAGMA synchronous")
        sync_mode = (await cursor.fetchone())[0]
        # NORMAL synchronous is 1
        assert sync_mode == 1

    await store.close()


@pytest.mark.asyncio
async def test_get_stats_by_workspace(tmp_path):
    db_file = tmp_path / "stats_ws.db"
    store = GraphStore(str(db_file))
    await store.initialize()

    ws1 = await store.create_workspace("WS1")
    ws2 = await store.create_workspace("WS2")

    sess1 = await store.create_session(ws1, "Sess1")
    sess2 = await store.create_session(ws2, "Sess2")

    svc1 = NetworkService.create(host_ip="192.168.1.10", port=80, protocol="tcp")
    await store.upsert_finding(sess1, svc1)

    svc2 = NetworkService.create(host_ip="10.0.0.1", port=443, protocol="tcp")
    await store.upsert_finding(sess2, svc2)

    stats_ws1 = await store.get_stats(workspace_id=ws1)
    stats_ws2 = await store.get_stats(workspace_id=ws2)
    stats_all = await store.get_stats()

    assert stats_ws1["network.service"] == 1
    assert stats_ws1["network.host"] == 1
    assert stats_ws1["total"] == 2

    assert stats_ws2["network.service"] == 1
    assert stats_ws2["network.host"] == 1
    assert stats_ws2["total"] == 2

    assert stats_all["network.service"] == 2
    assert stats_all["network.host"] == 2
    assert stats_all["total"] == 4

    await store.close()


@pytest.mark.asyncio
async def test_upsert_findings_batch(tmp_path):
    db_file = tmp_path / "batch_test.db"
    store = GraphStore(str(db_file))
    await store.initialize()

    ws_id = await store.create_workspace("BatchWS")
    sess_id = await store.create_session(ws_id, "BatchSess")

    findings = [
        NetworkService.create(host_ip="10.0.0.1", port=80, protocol="tcp"),
        NetworkService.create(host_ip="10.0.0.1", port=443, protocol="tcp"),
        NetworkService.create(host_ip="10.0.0.2", port=22, protocol="tcp"),
    ]

    callback_findings = []

    async def on_upsert_hook(s_id, finding):
        callback_findings.append((s_id, finding))

    store.on_upsert(on_upsert_hook)

    node_ids = await store.upsert_findings_batch(sess_id, findings)
    assert len(node_ids) == 3
    assert len(callback_findings) == 3

    # Check that services and parent hosts were created
    stats = await store.get_stats(sess_id)
    assert stats["network.service"] == 3
    assert stats["network.host"] == 2
    assert stats["total"] == 5

    await store.close()


@pytest.mark.asyncio
async def test_store_trusted_schema_and_permissions(tmp_path):
    db_file = str(tmp_path / "test_store.db")
    store = GraphStore(db_file)
    await store.initialize()

    # Check trusted_schema PRAGMA
    async with store._get_conn() as db:
        cursor = await db.execute("PRAGMA trusted_schema")
        row = await cursor.fetchone()
        assert row[0] == 0  # OFF

    # Check file permissions on DB
    mode = oct(os.stat(db_file).st_mode)[-3:]
    assert mode == "600"

    await store.close()


@pytest.mark.asyncio
async def test_default_session_preserves_user_sessions():
    """Verify that get_or_create_default_session preserves existing sessions and never auto-deletes."""
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()

    # Manually inject sessions into Default Workspace
    async with store._get_conn() as conn:
        await conn.execute(
            "INSERT INTO sessions (id, workspace_id, name) VALUES ('user-lab-1', ?, 'Custom Lab')",
            (ws_id,),
        )
        await conn.execute(
            "INSERT INTO sessions (id, workspace_id, name) VALUES ('user-lab-2', ?, 'Default Session (Imported 1)')",
            (ws_id,),
        )
        await conn.commit()

    # Verify 3 sessions exist prior to re-initialization
    sessions_before = await store.list_sessions(ws_id)
    assert len(sessions_before) == 3

    # Re-invoking get_or_create_default_session must safely return existing Default Session without deleting user sessions
    new_ws_id, new_sess_id = await store.get_or_create_default_session()
    assert new_ws_id == ws_id
    assert new_sess_id == sess_id

    sessions_after = await store.list_sessions(ws_id)
    assert len(sessions_after) == 3
    session_names = {s["name"] for s in sessions_after}
    assert "Default Session" in session_names
    assert "Custom Lab" in session_names
    assert "Default Session (Imported 1)" in session_names

    await store.close()


@pytest.mark.asyncio
async def test_schema_initialization_tables_columns_and_indices(tmp_path):
    """Verify that initialize() sets up all required tables, columns, and indices."""
    db_file = str(tmp_path / "init.db")
    store = GraphStore(db_file)
    await store.initialize()

    async with store._get_conn() as conn:
        cursor = await conn.execute("PRAGMA table_info(nodes)")
        node_cols = {row[1] for row in await cursor.fetchall()}
        assert "action_id" in node_cols
        assert "created_action_id" in node_cols
        assert "created_at" in node_cols
        assert "updated_at" in node_cols

        cursor = await conn.execute("PRAGMA table_info(edges)")
        edge_cols = {row[1] for row in await cursor.fetchall()}
        assert "action_id" in edge_cols
        assert "created_at" in edge_cols
        assert "updated_at" in edge_cols

        cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indices = {r[0] for r in await cursor.fetchall()}
        assert "idx_nodes_session_action" in indices
        assert "idx_edges_session_action" in indices

    await store.close()


@pytest.mark.asyncio
async def test_upsert_findings_with_action_id():
    """Verify that findings and relationships correctly record action_id."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    service = NetworkService.create(
        host_ip="10.0.0.1",
        port=80,
        protocol="tcp",
        service="http",
    )
    # NetworkService automatically links parent host
    node_ids = await store.upsert_findings_batch(sess_id, [service], action_id="act-test-42")
    assert len(node_ids) == 1

    async with store._get_conn() as conn:
        conn.row_factory = aiosqlite.Row
        # Check node action_id
        cursor = await conn.execute("SELECT * FROM nodes WHERE session_id = ?", (sess_id,))
        nodes = await cursor.fetchall()
        assert len(nodes) >= 1
        for n in nodes:
            assert n["action_id"] == "act-test-42"
            assert n["created_at"] is not None

        # Check edge action_id
        cursor = await conn.execute("SELECT * FROM edges WHERE session_id = ?", (sess_id,))
        edges = await cursor.fetchall()
        assert len(edges) >= 1
        for e in edges:
            assert e["action_id"] == "act-test-42"
            assert e["created_at"] is not None

    await store.close()


@pytest.mark.asyncio
async def test_store_temporal_schema_and_indexes():
    """Verify that temporal and anchor columns and indexes exist in the nodes table."""
    store = GraphStore(":memory:")
    await store.initialize()

    async with store._get_conn() as conn:
        conn.row_factory = aiosqlite.Row
        # Check column names
        cursor = await conn.execute("PRAGMA table_info(nodes)")
        cols = {r["name"] for r in await cursor.fetchall()}
        assert "observation_count" in cols
        assert "ttl_seconds" in cols
        assert "anchor_hash" in cols
        assert "last_seen_at" in cols
        assert "status" in cols

        # Check indexes
        cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indices = {r[0] for r in await cursor.fetchall()}
        assert "idx_nodes_anchor" in indices
        assert "idx_nodes_status" in indices
        assert "idx_nodes_last_seen" in indices

    await store.close()


@pytest.mark.asyncio
async def test_upsert_temporal_tracking_and_observation_count():
    """Verify that repeated observations increment observation_count and persist temporal fields."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    host = NetworkHost.create(ip="10.20.30.40", hostname="srv1.local")
    host.ttl_seconds = 1800
    host.anchor_hash = "tls:abcd1234ef5678"

    # First observation
    await store.upsert_finding(sess_id, host, action_id="act-1")
    node_before = await store.get_node(sess_id, store.generate_node_id(host.schema_type, host.pik))
    assert node_before is not None
    assert node_before["observation_count"] == 1
    assert node_before["ttl_seconds"] == 1800
    assert node_before["anchor_hash"] == "tls:abcd1234ef5678"
    assert node_before["last_seen_at"] is not None
    assert node_before["status"] == "confirmed"

    # Second observation (re-observation of same node)
    host2 = NetworkHost.create(ip="10.20.30.40", hostname="srv1-renamed.local")
    host2.ttl_seconds = 7200
    await store.upsert_finding(sess_id, host2, action_id="act-2")

    node_after = await store.get_node(sess_id, store.generate_node_id(host.schema_type, host.pik))
    assert node_after is not None
    assert node_after["observation_count"] == 2
    assert node_after["ttl_seconds"] == 7200
    assert node_after["anchor_hash"] == "tls:abcd1234ef5678"
    assert node_after["action_id"] == "act-2"

    await store.close()
