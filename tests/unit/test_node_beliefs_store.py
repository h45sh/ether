"""Unit tests for node_beliefs table and GraphStore persistence."""

import pytest

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


@pytest.mark.asyncio
async def test_node_beliefs_upsert_and_retrieve():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()
    host = NetworkHost.create(ip="10.0.0.1")
    node_id = await store.upsert_finding(sess_id, host)

    # Upsert belief
    await store.upsert_node_belief(
        node_id=node_id,
        session_id=sess_id,
        confidence=0.35,
        is_honeypot=1,
        is_tarpit=0,
        indicators=["port_entropy_sprawl", "cowrie_ssh_banner"],
    )

    belief = await store.get_node_belief(sess_id, node_id)
    assert belief is not None
    assert belief["node_id"] == node_id
    assert belief["session_id"] == sess_id
    assert belief["confidence"] == 0.35
    assert belief["is_honeypot"] is True
    assert belief["is_tarpit"] is False
    assert "port_entropy_sprawl" in belief["indicators"]

    # Update belief
    await store.upsert_node_belief(
        node_id=node_id,
        session_id=sess_id,
        confidence=0.95,
        is_honeypot=0,
        is_tarpit=0,
        indicators=["multi_tool_verified"],
    )
    updated = await store.get_node_belief(sess_id, node_id)
    assert updated["confidence"] == 0.95
    assert updated["is_honeypot"] is False
    assert updated["indicators"] == ["multi_tool_verified"]

    # List beliefs
    all_beliefs = await store.list_node_beliefs(sess_id)
    assert len(all_beliefs) == 1
    assert all_beliefs[0]["node_id"] == node_id

    await store.close()


@pytest.mark.asyncio
async def test_node_beliefs_foreign_key_cascade():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()
    host = NetworkHost.create(ip="10.0.0.2")
    node_id = await store.upsert_finding(sess_id, host)

    await store.upsert_node_belief(
        node_id=node_id,
        session_id=sess_id,
        confidence=0.5,
        is_honeypot=0,
        is_tarpit=1,
        indicators=["delay_tarpit"],
    )

    # Delete session; foreign key cascade should delete belief
    await store.delete_session(sess_id)

    belief = await store.get_node_belief(sess_id, node_id)
    assert belief is None

    await store.close()
