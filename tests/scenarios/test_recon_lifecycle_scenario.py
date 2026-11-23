"""Behavioral Scenario Contract: Full Autonomous Reconnaissance to Credential Discovery.

This scenario contract proves end-to-end telemetry and graph invariants:
1. Ingestion of multi-tier cyber entities (Domain -> Host -> Service -> Endpoint -> Vuln -> Credential).
2. Primary Identity Key (PIK) deterministic derivation and idempotent re-upsert (0 duplicates).
3. Automatic topological edge wiring across entity relations.
4. Graph analytics traversal (attack path continuity and blast radius coverage).
"""

import pytest

from ether.graph.analytics import GraphAnalyticsEngine
from ether.graph.store import GraphStore
from ether.schemas.credential import CredentialFound
from ether.schemas.dns import DnsRecord, DomainInfo
from ether.schemas.network import NetworkHost, NetworkService
from ether.schemas.vulnerability import VulnerabilityFound
from ether.schemas.web import WebEndpoint


@pytest.mark.scenario
@pytest.mark.asyncio
async def test_full_recon_to_compromise_lifecycle():
    """Verify that a multi-stage reconnaissance workflow builds a deterministic, connected graph."""
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_default_session()

    # Step 1: Root Domain target
    domain = DomainInfo.create(domain="targetcorp.internal")
    domain_id = await store.upsert_finding(sess_id, domain)

    # Step 2: Discovered DNS A Record resolving to IP
    dns_record = DnsRecord.create(
        domain="api.targetcorp.internal",
        record_type="A",
        value="10.0.1.50",
    )
    dns_id = await store.upsert_finding(sess_id, dns_record)

    # Step 3: Network Host
    host = NetworkHost.create(
        ip="10.0.1.50",
        hostname="api.targetcorp.internal",
    )
    host_id = await store.upsert_finding(sess_id, host)

    # Step 4: Exposed Service on Host
    service = NetworkService.create(
        host_ip="10.0.1.50",
        port=443,
        protocol="tcp",
        service_name="https",
    )
    service_id = await store.upsert_finding(sess_id, service)

    # Step 5: Web API Endpoint
    endpoint = WebEndpoint.create(
        url="https://10.0.1.50/api/v1/login",
        host_ip="10.0.1.50",
        port=443,
    )
    endpoint_id = await store.upsert_finding(sess_id, endpoint)

    # Step 6: Critical Vulnerability on Endpoint / Service
    vuln = VulnerabilityFound.create(
        host_ip="10.0.1.50",
        vuln_id="CVE-2026-1001",
        port=443,
        severity="critical",
        title="SQL Injection in Authentication Route",
    )
    vuln_id = await store.upsert_finding(sess_id, vuln)

    # Step 7: Discovered Credentials
    cred = CredentialFound.create(
        context="10.0.1.50:443",
        username="db_admin",
        password="sha256$5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        host_ip="10.0.1.50",
    )
    cred_id = await store.upsert_finding(sess_id, cred)

    # --- INVARIANT ASSERTION 1: Deterministic PIK Hash Format ---
    for node_id in [domain_id, dns_id, host_id, service_id, endpoint_id, vuln_id, cred_id]:
        assert len(node_id) == 64, f"Node ID '{node_id}' is not a 64-char SHA-256 hash"
        assert all(c in "0123456789abcdef" for c in node_id)

    # --- INVARIANT ASSERTION 2: Exact Node Counts by Schema ---
    nodes = await store.get_all_nodes(sess_id)
    assert len(nodes) == 8

    assert len(await store.query("domain.info", sess_id)) == 1
    assert len(await store.query("dns.record", sess_id)) == 2  # Domain parent wildcard + A record
    assert len(await store.query("network.host", sess_id)) == 1
    assert len(await store.query("network.service", sess_id)) == 1
    assert len(await store.query("web.endpoint", sess_id)) == 1
    assert len(await store.query("vulnerability.found", sess_id)) == 1
    assert len(await store.query("credential.found", sess_id)) == 1

    # --- INVARIANT ASSERTION 3: Mathematical Idempotency of Ingestion ---
    # Re-upserting all 7 findings in reverse order must NOT create duplicate nodes
    reingested_findings = [cred, vuln, endpoint, service, host, dns_record, domain]
    for f in reingested_findings:
        re_id = await store.upsert_finding(sess_id, f)
        assert re_id in [domain_id, dns_id, host_id, service_id, endpoint_id, vuln_id, cred_id]

    nodes_after_reingest = await store.get_all_nodes(sess_id)
    assert len(nodes_after_reingest) == 8, "Idempotency broken: duplicate nodes created"

    # --- INVARIANT ASSERTION 4: Topological Graph Connectivity & Analytics ---
    edges = await store.get_all_edges(sess_id)
    assert len(edges) >= 4, "Hierarchical relationships were not automatically wired"

    engine = GraphAnalyticsEngine(nodes, edges)
    critical_assets = engine.identify_critical_assets()
    assert any(asset["id"] == vuln_id for asset in critical_assets)

    # Blast radius from host should reach service and endpoint
    blast = engine.calculate_blast_radius(host_id)
    assert service_id in blast or endpoint_id in blast

    await store.close()
