import pytest

from ether.graph.store import GraphStore
from ether.schemas.dns import DnsRecord
from ether.schemas.network import NetworkService, TLSCertificate
from ether.schemas.web import WebEndpoint


@pytest.mark.fast
def test_schema_anchor_hash_derivation():
    # 1. NetworkService with TLS cert
    svc_tls = NetworkService.create(
        host_ip="192.168.1.50",
        port=443,
        service_name="https",
        tls_cert_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert svc_tls.anchor_hash == (
        "tls:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    # 2. NetworkService with SSH hostkey
    svc_ssh = NetworkService.create(
        host_ip="192.168.1.50",
        port=22,
        service_name="ssh",
        ssh_hostkey_fingerprint="SHA256:abc123xyz",
    )
    assert svc_ssh.anchor_hash == "ssh:SHA256:abc123xyz"

    # 3. TLSCertificate
    tls_cert = TLSCertificate.create(
        fingerprint="aabbccdd11223344",
        host_ip="192.168.1.50",
        port=443,
    )
    assert tls_cert.anchor_hash == "tls:aabbccdd11223344"

    # 4. WebEndpoint with favicon hash
    web = WebEndpoint.create(
        url="https://192.168.1.50/login",
        favicon_hash="987654321",
    )
    assert web.anchor_hash == "favicon:987654321"

    # 5. DnsRecord with SOA serial
    soa = DnsRecord.create(
        domain="example.com",
        record_type="SOA",
        value="ns1.example.com admin.example.com 2026112201 7200 3600 1209600 3600",
        soa_serial="2026112201",
    )
    assert soa.anchor_hash == "soa:2026112201"


@pytest.mark.asyncio
async def test_cross_ip_identity_migration():
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    cert_fingerprint = "cert_sha256_abcdef1234567890"

    # Step 1: Initial observation of HTTPS service on IP 192.168.1.10
    svc_v1 = NetworkService.create(
        host_ip="192.168.1.10",
        port=443,
        service_name="https",
        tls_cert_sha256=cert_fingerprint,
    )
    ids_v1 = await store.upsert_findings_batch(sess_id, [svc_v1], action_id="act-1")
    node_v1_id = ids_v1[0]

    # Verify initial state: 1 confirmed service node
    active_nodes = await store.get_all_nodes(
        sess_id, schema_type="network.service", include_stale=False
    )
    assert len(active_nodes) == 1
    assert active_nodes[0]["id"] == node_v1_id
    assert active_nodes[0]["status"] == "confirmed"

    # Step 2: Cross-IP migration — same TLS certificate reappears on IP 10.0.0.99
    svc_v2 = NetworkService.create(
        host_ip="10.0.0.99",
        port=443,
        service_name="https",
        tls_cert_sha256=cert_fingerprint,
    )
    ids_v2 = await store.upsert_findings_batch(sess_id, [svc_v2], action_id="act-2")
    node_v2_id = ids_v2[0]

    assert node_v1_id != node_v2_id

    # Verify stale node exclusion in standard query
    active_nodes_after = await store.get_all_nodes(
        sess_id, schema_type="network.service", include_stale=False
    )
    assert len(active_nodes_after) == 1
    assert active_nodes_after[0]["id"] == node_v2_id
    assert active_nodes_after[0]["status"] == "confirmed"

    # Verify full node audit (with stale nodes)
    all_nodes = await store.get_all_nodes(
        sess_id, schema_type="network.service", include_stale=True
    )
    assert len(all_nodes) == 2
    node_v1_record = next(n for n in all_nodes if n["id"] == node_v1_id)
    node_v2_record = next(n for n in all_nodes if n["id"] == node_v2_id)
    assert node_v1_record["status"] == "stale"
    assert node_v2_record["status"] == "confirmed"

    # Step 3: Verify anchored_identity edge was wired
    edges = await store.get_all_edges(sess_id)
    migration_edges = [e for e in edges if e["relation_type"] == "anchored_identity"]
    assert len(migration_edges) == 1
    assert migration_edges[0]["source_id"] == node_v1_id
    assert migration_edges[0]["target_id"] == node_v2_id

    # Step 4: Verify migration event logged
    migrations = await store.get_anchored_migrations(sess_id)
    assert len(migrations) == 1
    assert migrations[0]["anchor_hash"] == f"tls:{cert_fingerprint}"
    assert migrations[0]["from_node_id"] == node_v1_id
    assert migrations[0]["to_node_id"] == node_v2_id

    # Step 5: Re-observing node_v2 does not create duplicate edges or events
    await store.upsert_findings_batch(sess_id, [svc_v2], action_id="act-3")
    migrations_again = await store.get_anchored_migrations(sess_id)
    assert len(migrations_again) == 1

    # Step 6: Chained migration to 172.16.5.5
    svc_v3 = NetworkService.create(
        host_ip="172.16.5.5",
        port=443,
        service_name="https",
        tls_cert_sha256=cert_fingerprint,
    )
    ids_v3 = await store.upsert_findings_batch(sess_id, [svc_v3], action_id="act-4")
    node_v3_id = ids_v3[0]

    all_nodes_v3 = await store.get_all_nodes(
        sess_id, schema_type="network.service", include_stale=True
    )
    assert len(all_nodes_v3) == 3
    node_v2_record = next(n for n in all_nodes_v3 if n["id"] == node_v2_id)
    node_v3_record = next(n for n in all_nodes_v3 if n["id"] == node_v3_id)
    assert node_v2_record["status"] == "stale"
    assert node_v3_record["status"] == "confirmed"

    edges_v3 = await store.get_all_edges(sess_id)
    migration_edges_v3 = [e for e in edges_v3 if e["relation_type"] == "anchored_identity"]
    # Should have edges v1->v2 and v2->v3 (and/or v1->v3)
    assert any(
        e["source_id"] == node_v2_id and e["target_id"] == node_v3_id for e in migration_edges_v3
    )

    await store.close()
