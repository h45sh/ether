"""Unit tests for GraphStore temporal state decay and stale node filtering."""

from datetime import UTC, datetime, timedelta

import pytest

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


@pytest.mark.asyncio
async def test_reconcile_state_decay_basic():
    """Verify that nodes exceeding TTL transition from confirmed to stale."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    t0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)

    host = NetworkHost.create(ip="10.0.0.1")
    host.ttl_seconds = 100
    node_id = await store.upsert_finding(sess_id, host)

    # Set last_seen_at explicitly to t0
    async with store._get_conn() as conn:
        await conn.execute(
            "UPDATE nodes SET last_seen_at = ? WHERE session_id = ? AND id = ?",
            (t0.strftime("%Y-%m-%d %H:%M:%S"), sess_id, node_id),
        )
        await conn.commit()

    # Reconcile within TTL (t0 + 50s) -> should remain confirmed
    res_within = await store.reconcile_state_decay(sess_id, now=t0 + timedelta(seconds=50))
    assert res_within["reconciled_count"] == 0
    assert res_within["status_breakdown"]["confirmed"] == 1

    node = await store.get_node(sess_id, node_id)
    assert node["status"] == "confirmed"

    # Reconcile beyond TTL (t0 + 150s) -> should transition to stale
    res_beyond = await store.reconcile_state_decay(sess_id, now=t0 + timedelta(seconds=150))
    assert res_beyond["reconciled_count"] == 1
    assert res_beyond["transitions"][0]["to"] == "stale"
    assert res_beyond["status_breakdown"]["stale"] == 1

    node = await store.get_node(sess_id, node_id)
    assert node["status"] == "stale"

    await store.close()


@pytest.mark.asyncio
async def test_reconcile_state_decay_flapping():
    """Verify that nodes with oscillating observations transition to flapping."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    t0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)

    # Create host with oscillation indicator
    host = NetworkHost.create(ip="10.0.0.2")
    host.ttl_seconds = 100
    host.data["oscillations"] = 2
    node_id = await store.upsert_finding(sess_id, host)

    async with store._get_conn() as conn:
        await conn.execute(
            "UPDATE nodes SET last_seen_at = ? WHERE session_id = ? AND id = ?",
            (t0.strftime("%Y-%m-%d %H:%M:%S"), sess_id, node_id),
        )
        await conn.commit()

    # Reconcile beyond 1 TTL -> should transition to flapping
    res = await store.reconcile_state_decay(sess_id, now=t0 + timedelta(seconds=150))
    assert res["reconciled_count"] == 1
    assert res["transitions"][0]["to"] == "flapping"

    node = await store.get_node(sess_id, node_id)
    assert node["status"] == "flapping"

    # Reconcile beyond 2 * TTL -> flapping transitions to stale
    res2 = await store.reconcile_state_decay(sess_id, now=t0 + timedelta(seconds=250))
    assert res2["reconciled_count"] == 1
    assert res2["transitions"][0]["to"] == "stale"

    node = await store.get_node(sess_id, node_id)
    assert node["status"] == "stale"

    await store.close()


@pytest.mark.asyncio
async def test_get_all_nodes_stale_filtering():
    """Verify get_all_nodes excludes stale nodes unless include_stale=True."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    t0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)

    h1 = NetworkHost.create(ip="10.0.0.1")
    h1.ttl_seconds = 50
    h2 = NetworkHost.create(ip="10.0.0.2")
    h2.ttl_seconds = 500

    id1 = await store.upsert_finding(sess_id, h1)
    await store.upsert_finding(sess_id, h2)

    async with store._get_conn() as conn:
        await conn.execute(
            "UPDATE nodes SET last_seen_at = ? WHERE session_id = ? AND id = ?",
            (t0.strftime("%Y-%m-%d %H:%M:%S"), sess_id, id1),
        )
        await conn.commit()

    # Reconcile at t0 + 100s -> h1 decays to stale, h2 remains confirmed
    await store.reconcile_state_decay(sess_id, now=t0 + timedelta(seconds=100))

    nodes_default = await store.get_all_nodes(sess_id, include_stale=False)
    assert len(nodes_default) == 1
    assert nodes_default[0]["id"] != id1

    nodes_all = await store.get_all_nodes(sess_id, include_stale=True)
    assert len(nodes_all) == 2

    await store.close()


@pytest.mark.asyncio
async def test_prune_stale_nodes():
    """Verify prune_stale_nodes permanently purges expired stale nodes."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    t0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)

    h1 = NetworkHost.create(ip="10.0.0.1")
    h1.ttl_seconds = 10
    id1 = await store.upsert_finding(sess_id, h1)

    # Set last_seen_at to t0
    async with store._get_conn() as conn:
        await conn.execute(
            "UPDATE nodes SET last_seen_at = ? WHERE session_id = ? AND id = ?",
            (t0.strftime("%Y-%m-%d %H:%M:%S"), sess_id, id1),
        )
        await conn.commit()

    # Decay to stale
    await store.reconcile_state_decay(sess_id, now=t0 + timedelta(seconds=20))
    node = await store.get_node(sess_id, id1)
    assert node["status"] == "stale"

    # Prune with max_age_seconds=10 at t0 + 50s
    pruned_count = await store.prune_stale_nodes(
        sess_id, max_age_seconds=10, now=t0 + timedelta(seconds=50)
    )
    assert pruned_count == 1

    node_after = await store.get_node(sess_id, id1)
    assert node_after is None

    await store.close()
