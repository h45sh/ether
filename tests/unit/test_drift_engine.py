"""Unit tests for native architectural drift engine and baseline export."""

from pathlib import Path

import pytest

from ether.drift.engine import audit_drift, export_baseline
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.asyncio
async def test_drift_zero_score_on_identical_baseline(tmp_path: Path):
    """Verify identical session graph against its exported baseline yields 0.0 drift score."""
    db_file = str(tmp_path / "drift_test.db")
    store = GraphStore(db_file)
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_workspace_session("DriftWS", "BaseSess")

    host = NetworkHost.create(ip="10.0.0.1", hostname="gw.corp")
    svc = NetworkService.create(host_ip="10.0.0.1", port=443, protocol="tcp", service_name="https")
    await store.upsert_finding(sess_id, host)
    await store.upsert_finding(sess_id, svc)

    baseline_path = str(tmp_path / "baseline.json")
    baseline = await export_baseline(store, sess_id, out_path=baseline_path)
    assert len(baseline["nodes"]) >= 2

    # Audit same session against baseline
    report = await audit_drift(store, sess_id, baseline, mode="topology")
    assert report.drift_score == 0.0
    assert len(report.discrepancies) == 0

    await store.close()


@pytest.mark.asyncio
async def test_drift_score_and_findings_on_divergence(tmp_path: Path):
    """Verify unexpected open port and missing host produce non-zero drift score and AuditDrift findings."""
    db_file = str(tmp_path / "drift_div.db")
    store = GraphStore(db_file)
    await store.initialize()
    ws_id, sess_a = await store.get_or_create_workspace_session("DriftWS", "SessionA")
    _, sess_b = await store.get_or_create_workspace_session("DriftWS", "SessionB")

    # Baseline: host 10.0.0.1 (ports 80, 443) and host 10.0.0.2 (port 22)
    await store.upsert_finding(sess_a, NetworkHost.create(ip="10.0.0.1"))
    await store.upsert_finding(
        sess_a, NetworkService.create(host_ip="10.0.0.1", port=80, protocol="tcp")
    )
    await store.upsert_finding(
        sess_a, NetworkService.create(host_ip="10.0.0.1", port=443, protocol="tcp")
    )
    await store.upsert_finding(sess_a, NetworkHost.create(ip="10.0.0.2"))
    await store.upsert_finding(
        sess_a, NetworkService.create(host_ip="10.0.0.2", port=22, protocol="tcp")
    )

    baseline = await export_baseline(store, sess_a)

    # Observed in Session B:
    # 10.0.0.1 is present with port 80 and unexpected rogue port 8080.
    # 10.0.0.2 is missing entirely.
    await store.upsert_finding(sess_b, NetworkHost.create(ip="10.0.0.1"))
    await store.upsert_finding(
        sess_b, NetworkService.create(host_ip="10.0.0.1", port=80, protocol="tcp")
    )
    await store.upsert_finding(
        sess_b, NetworkService.create(host_ip="10.0.0.1", port=8080, protocol="tcp")
    )

    report = await audit_drift(store, sess_b, baseline, mode="topology", record_findings=True)

    assert 0.0 < report.drift_score <= 1.0
    assert len(report.discrepancies) >= 2

    discrepancy_types = [d.pik["discrepancy_type"] for d in report.discrepancies]
    assert any("rogue_service" in t or "unexpected" in t for t in discrepancy_types)
    assert any("missing" in t for t in discrepancy_types)

    # Verify AuditDrift findings are saved in GraphStore
    nodes = await store.get_all_nodes(sess_b, schema_type="audit.drift")
    assert len(nodes) >= 2

    await store.close()


@pytest.mark.asyncio
async def test_drift_strict_mode_version_discrepancy(tmp_path: Path):
    """Verify strict mode flags banner / version differences for matching nodes."""
    db_file = str(tmp_path / "drift_strict.db")
    store = GraphStore(db_file)
    await store.initialize()
    ws_id, sess_base = await store.get_or_create_workspace_session("DriftWS", "StrictBase")
    _, sess_obs = await store.get_or_create_workspace_session("DriftWS", "StrictObs")

    # Baseline service version
    await store.upsert_finding(
        sess_base,
        NetworkService.create(
            host_ip="10.0.0.5", port=22, protocol="tcp", service_name="OpenSSH 8.9"
        ),
    )
    baseline = await export_baseline(store, sess_base)

    # Observed service has downgraded version
    await store.upsert_finding(
        sess_obs,
        NetworkService.create(
            host_ip="10.0.0.5", port=22, protocol="tcp", service_name="OpenSSH 7.2"
        ),
    )

    # Topology mode should yield 0 drift (same host & port)
    topo_report = await audit_drift(store, sess_obs, baseline, mode="topology")
    assert topo_report.drift_score == 0.0

    # Strict mode should flag attribute divergence
    strict_report = await audit_drift(store, sess_obs, baseline, mode="strict")
    assert strict_report.drift_score > 0.0
    assert any(
        "version_divergence" in d.pik["discrepancy_type"] for d in strict_report.discrepancies
    )

    await store.close()


@pytest.mark.asyncio
async def test_drift_json_string_baseline_and_batch_persist(tmp_path: Path):
    """Verify audit_drift accepts a JSON-string baseline and batch-persists discrepancies."""
    import json

    db_file = str(tmp_path / "drift_json_str.db")
    store = GraphStore(db_file)
    await store.initialize()
    _, sess_base = await store.get_or_create_workspace_session("DriftWS", "JsonBase")
    _, sess_obs = await store.get_or_create_workspace_session("DriftWS", "JsonObs")

    await store.upsert_finding(sess_base, NetworkHost.create(ip="10.0.0.10"))
    baseline_dict = await export_baseline(store, sess_base)
    baseline_json_str = json.dumps(baseline_dict)

    await store.upsert_finding(sess_obs, NetworkHost.create(ip="10.0.0.11"))
    report = await audit_drift(
        store, sess_obs, baseline_json_str, mode="topology", record_findings=True
    )
    assert report.drift_score > 0.0
    assert len(report.discrepancies) == 2

    saved = await store.get_all_nodes(sess_obs, schema_type="audit.drift")
    assert len(saved) == 2

    await store.close()


@pytest.mark.asyncio
async def test_drift_strict_mode_http_security_headers_and_schema_exports(tmp_path: Path):
    """Verify strict mode flags missing HTTP security headers and schemas exports AuditDrift & TLSCipherSuite."""
    from ether.schemas import AuditDrift, TLSCipherSuite, WebEndpoint

    assert AuditDrift is not None
    assert TLSCipherSuite is not None

    db_file = str(tmp_path / "drift_headers.db")
    store = GraphStore(db_file)
    await store.initialize()
    _, sess_base = await store.get_or_create_workspace_session("DriftWS", "HdrBase")
    _, sess_obs = await store.get_or_create_workspace_session("DriftWS", "HdrObs")

    await store.upsert_finding(
        sess_base,
        WebEndpoint.create(
            url="https://app.example.com",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
            },
        ),
    )
    baseline = await export_baseline(store, sess_base)

    await store.upsert_finding(
        sess_obs,
        WebEndpoint.create(
            url="https://app.example.com",
            headers={"Content-Security-Policy": "default-src 'self'"},
        ),
    )

    report = await audit_drift(store, sess_obs, baseline, mode="strict")
    assert report.drift_score > 0.0
    assert any(d.pik["discrepancy_type"] == "missing_security_header" for d in report.discrepancies)

    await store.close()
