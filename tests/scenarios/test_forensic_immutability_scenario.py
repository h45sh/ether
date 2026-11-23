"""Behavioral Scenario Contract: Forensic Session Seal and Immutability Defense.

Verifies the security invariant from AGENTS.md Section 9:
"Forensic Session Immutability: Sessions marked as closed in the database are
forensically sealed. Mutation attempts against closed sessions raise PermissionError."
"""

import pytest

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.scenario
@pytest.mark.asyncio
async def test_forensic_session_immutability_lifecycle():
    """Verify that closing a session forensically seals it against any data mutation."""
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id = await store.create_workspace("ForensicInvestigation")
    sess_id = await store.create_session(ws_id, "SealedEvidenceSession")

    # 1. Normal state: active session accepts findings
    host = NetworkHost.create(ip="10.99.0.10", hostname="evidence.corp")
    host_id = await store.upsert_finding(sess_id, host)
    assert host_id is not None

    nodes = await store.get_all_nodes(sess_id)
    assert len(nodes) == 1

    # 2. Forensically seal the session
    await store.close_session(sess_id)
    assert await store.is_session_closed(sess_id) is True

    # 3. Adversarial mutation attempts against sealed session
    new_service = NetworkService.create(
        host_ip="10.99.0.10",
        port=22,
        protocol="tcp",
        service_name="ssh",
    )

    with pytest.raises(PermissionError) as exc_info:
        await store.upsert_finding(sess_id, new_service)
    assert "forensically sealed" in str(exc_info.value)

    # 4. Verify existing data was untouched and remains intact
    nodes_after_tamper = await store.get_all_nodes(sess_id)
    assert len(nodes_after_tamper) == 1
    assert nodes_after_tamper[0]["id"] == host_id

    # 5. Controlled legal unseal / reopen
    await store.reopen_session(sess_id)
    assert await store.is_session_closed(sess_id) is False

    # Upsert should now succeed post-reopen
    service_id = await store.upsert_finding(sess_id, new_service)
    assert service_id is not None

    nodes_post_reopen = await store.get_all_nodes(sess_id)
    assert len(nodes_post_reopen) == 2

    await store.close()
