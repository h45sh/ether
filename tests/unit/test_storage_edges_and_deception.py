"""Unit tests for atomic permissions, GraphStore edge auto-wiring, honeypot detection, and tcp_probe."""

import os
import stat

import pytest

from ether.graph.analytics import GraphAnalyticsEngine
from ether.graph.store import GraphStore
from ether.paths import atomic_create_file
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkService
from ether.schemas.web import WebEndpoint
from tools.tcp_probe.adapter import TcpProbeAdapter


def test_atomic_create_file_overwrite_mode(tmp_path):
    target = str(tmp_path / "test_secret.txt")
    # Pre-create file with 0o644
    with open(target, "w", encoding="utf-8") as f:
        f.write("old_public_content")
    os.chmod(target, 0o644)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644

    # Overwrite with atomic_create_file
    atomic_create_file(target, "new_secret_content")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    with open(target, "r", encoding="utf-8") as f:
        assert f.read() == "new_secret_content"


@pytest.mark.asyncio
async def test_graphstore_permissions_and_auto_schema(tmp_path):
    db_dir = tmp_path / "custom_ether_db"
    db_path = str(db_dir / "ether_test.db")

    store = GraphStore(db_path)
    await store.initialize()
    session = await store.get_session("non_existent")
    assert session is None

    # Verify db directory mode is 0o700
    assert stat.S_IMODE(os.stat(str(db_dir)).st_mode) == 0o700
    # Verify db file mode is 0o600
    assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o600
    await store.close()


@pytest.mark.asyncio
async def test_graphstore_deterministic_edge_wiring():
    store = GraphStore(":memory:")
    await store.initialize()
    _, session_id = await store.get_or_create_default_session()

    # Upsert findings without explicit parent declarations
    svc = NetworkService.create(host_ip="10.0.0.5", port=443, protocol="tcp", service_name="https")
    ep = WebEndpoint.create(url="https://10.0.0.5:443/login", host_ip="10.0.0.5", port=443)
    vuln = BaseFinding(
        schema_type="vulnerability",
        pik={"id": "CVE-2023-1234", "url": "https://10.0.0.5:443/login"},
        data={"title": "Auth Bypass", "url": "https://10.0.0.5:443/login"},
    )

    await store.upsert_findings_batch(session_id, [svc, ep, vuln])

    edges = await store.get_all_edges(session_id)
    edge_types = [e["relation_type"] for e in edges]
    assert "has_service" in edge_types
    assert "hosts_endpoint" in edge_types
    assert "has_vulnerability" in edge_types
    await store.close()


def test_deception_analytics_cowrie_and_tarpit():
    nodes = [
        {
            "id": "node_ssh",
            "schema_type": "network.service",
            "pik_json": '{"host_ip": "10.0.0.10", "port": 22}',
            "data_json": '{"service": "ssh", "banner": "SSH-2.0-Cowrie SSH Honeypot"}',
        },
        {
            "id": "node_tarpit",
            "schema_type": "network.service",
            "pik_json": '{"host_ip": "10.0.0.10", "port": 8888}',
            "data_json": '{"service": "http", "latency_sec": 66.5, "is_tarpit": true}',
        },
    ]
    edges = []
    engine = GraphAnalyticsEngine(nodes, edges)
    beliefs = engine.evaluate_deception()

    assert beliefs["node_ssh"]["is_honeypot"] is True
    assert any("cowrie" in ind for ind in beliefs["node_ssh"]["indicators"])

    assert beliefs["node_tarpit"]["is_tarpit"] is True
    assert any("tarpit" in ind for ind in beliefs["node_tarpit"]["indicators"])


def test_tcp_probe_adapter_validation():
    adapter = TcpProbeAdapter()
    assert adapter.validate_install() is True
    cmd = adapter.build_command(
        BaseFinding(schema_type="network.host", pik={"ip": "1.2.3.4"}, data={}),
        {"port": 22},
    )
    assert cmd == ["tcp_probe", "1.2.3.4:22"]
