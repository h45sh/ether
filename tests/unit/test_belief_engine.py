"""Unit tests for Bayesian belief engine and honeypot/deception detection in GraphAnalyticsEngine."""

import pytest

from ether.graph.analytics import GraphAnalyticsEngine
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService


def test_legitimate_host_evaluation():
    nodes = [
        {"id": "host_1", "schema_type": "network.host", "data": {"ip": "10.0.0.5"}},
        {
            "id": "svc_80",
            "schema_type": "network.service",
            "data": {"host_ip": "10.0.0.5", "port": 80, "service_name": "http"},
            "observation_count": 2,
        },
    ]
    edges = [
        {"source_id": "host_1", "target_id": "svc_80", "relation_type": "hosts"},
    ]

    engine = GraphAnalyticsEngine(nodes, edges)
    beliefs = engine.evaluate_deception()

    assert beliefs["host_1"]["is_honeypot"] is False
    assert beliefs["host_1"]["confidence"] >= 0.80

    assert beliefs["svc_80"]["is_honeypot"] is False
    assert beliefs["svc_80"]["confidence"] >= 0.90
    assert "multi_tool_corroborated" in beliefs["svc_80"]["indicators"]


def test_honeypot_port_sprawl_detection():
    # Simulate a host with 120 fake open ports
    nodes = [{"id": "host_ghost", "schema_type": "network.host", "data": {"ip": "192.168.1.100"}}]
    edges = []

    for p in range(1, 121):
        svc_id = f"svc_{p}"
        nodes.append({
            "id": svc_id,
            "schema_type": "network.service",
            "data": {"host_ip": "192.168.1.100", "port": p},
        })
        edges.append({
            "source_id": "host_ghost",
            "target_id": svc_id,
            "relation_type": "hosts",
        })

    engine = GraphAnalyticsEngine(nodes, edges)
    beliefs = engine.evaluate_deception()

    assert beliefs["host_ghost"]["is_honeypot"] is True
    assert beliefs["host_ghost"]["confidence"] <= 0.20
    assert any("excessive_open_ports" in ind for ind in beliefs["host_ghost"]["indicators"])

    assert beliefs["svc_1"]["is_honeypot"] is True
    assert beliefs["svc_1"]["confidence"] <= 0.20


def test_honeypot_banner_signature_detection():
    nodes = [
        {"id": "host_1", "schema_type": "network.host", "data": {"ip": "10.0.0.9"}},
        {
            "id": "svc_2222",
            "schema_type": "network.service",
            "data": {
                "host_ip": "10.0.0.9",
                "port": 2222,
                "banner": "SSH-2.0-Cowrie SSH Honeypot",
            },
        },
    ]
    edges = [
        {"source_id": "host_1", "target_id": "svc_2222", "relation_type": "hosts"},
    ]

    engine = GraphAnalyticsEngine(nodes, edges)
    beliefs = engine.evaluate_deception()

    assert beliefs["svc_2222"]["is_honeypot"] is True
    assert beliefs["svc_2222"]["confidence"] <= 0.15
    assert "honeypot_signature:cowrie" in beliefs["svc_2222"]["indicators"]


@pytest.mark.asyncio
async def test_evaluate_and_persist_integration():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()
    host = NetworkHost.create(ip="10.0.0.50")
    host_id = await store.upsert_finding(sess_id, host)

    svc = NetworkService.create(
        host_ip="10.0.0.50",
        port=80,
        service_name="http",
    )
    svc_id = await store.upsert_finding(sess_id, svc)

    persisted = await GraphAnalyticsEngine.evaluate_and_persist(store, sess_id)
    assert len(persisted) >= 2

    host_belief = await store.get_node_belief(sess_id, host_id)
    assert host_belief is not None
    assert host_belief["confidence"] >= 0.70

    await store.close()
