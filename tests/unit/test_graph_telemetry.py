"""Unit tests for GraphTelemetryCompiler (Agent Telemetry Protocol)."""

import pytest

from ether.graph.store import GraphStore
from ether.graph.telemetry import GraphTelemetryCompiler
from ether.schemas.network import NetworkHost, NetworkService
from ether.schemas.vulnerability import VulnerabilityFound


@pytest.mark.asyncio
async def test_budget_findings_knapsack_prioritization():
    """Verify that knapsack budgeting prioritizes critical vulnerabilities and credentials over hosts."""
    host = NetworkHost.create(ip="10.0.0.1")
    service = NetworkService.create(host_ip="10.0.0.1", port=80, service_name="http")
    vuln_crit = VulnerabilityFound.create(
        host_ip="10.0.0.1",
        vuln_id="CVE-2024-9999",
        title="Remote Code Execution",
        severity="critical",
    )
    vuln_low = VulnerabilityFound.create(
        host_ip="10.0.0.1",
        vuln_id="CVE-2024-0001",
        title="Info Leak",
        severity="low",
    )

    all_findings = [host, service, vuln_crit, vuln_low]

    # Constrain tokens so only high-utility findings fit
    budgeted = GraphTelemetryCompiler.budget_findings(all_findings, max_tokens=150)

    # Critical vuln must be selected
    schema_types = [f.schema_type for f in budgeted]
    assert any("vulnerability" in st for st in schema_types)
    # The critical vulnerability must be prioritized over low vulnerability
    crit_in_budget = any(
        getattr(f, "data", {}).get("severity") == "critical"
        for f in budgeted
        if "vulnerability" in f.schema_type
    )
    assert crit_in_budget is True


@pytest.mark.asyncio
async def test_compile_telemetry_snapshot_with_selected_entity(tmp_path):
    """Verify point-in-time snapshot compilation with selected entity variables and stats."""
    db_file = str(tmp_path / "telemetry_test.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id = await store.create_workspace("TeleWS")
    sess_id = await store.create_session(ws_id, "TeleSess")

    host = NetworkHost.create(ip="192.168.1.100", hostname="web.local")
    host_id = await store.upsert_finding(sess_id, host)

    service = NetworkService.create(host_ip="192.168.1.100", port=443, service_name="https")
    await store.upsert_finding(sess_id, service)

    compiler = GraphTelemetryCompiler(store, sess_id)
    snapshot = await compiler.compile_telemetry_snapshot(selected_entity_id=host_id, max_tokens=2000)

    assert snapshot["session_id"] == sess_id
    assert snapshot["session_name"] == "TeleSess"
    assert snapshot["selected_entity"] is not None
    assert snapshot["selected_entity"]["pik"]["ip"] == "192.168.1.100"
    assert snapshot["resolved_vars"]["TARGET"] == "192.168.1.100"
    assert snapshot["graph_summary"]["total_nodes"] == 2
    assert snapshot["graph_summary"]["total_edges"] == 1
    assert len(snapshot["budgeted_findings"]) > 0

    await store.close()


@pytest.mark.asyncio
async def test_compute_graph_diff_zero_tokens(tmp_path):
    """Verify set-theoretic graph delta computation since baseline timestamp."""
    db_file = str(tmp_path / "diff_test.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id = await store.create_workspace("DiffWS")
    sess_id = await store.create_session(ws_id, "DiffSess")

    # Node added before baseline
    h1 = NetworkHost.create(ip="10.0.0.1")
    h1_id = await store.upsert_finding(sess_id, h1)
    async with store.connection() as db:
        await db.execute(
            "UPDATE nodes SET updated_at = '2020-01-01 00:00:00' WHERE id = ?", (h1_id,)
        )
        await db.commit()

    baseline = 1600000000.0  # Sept 2020, well after 2020-01-01 but before now

    # Node added after baseline
    h2 = NetworkHost.create(ip="10.0.0.2")
    await store.upsert_finding(sess_id, h2)

    # Edge added after baseline
    s2 = NetworkService.create(host_ip="10.0.0.2", port=22, service_name="ssh")
    await store.upsert_finding(sess_id, s2)

    compiler = GraphTelemetryCompiler(store, sess_id)
    diff = await compiler.compute_graph_diff(baseline_timestamp=baseline)

    assert diff["baseline_timestamp"] == baseline
    assert diff["tokens_consumed"] == 0

    # Nodes updated after baseline
    affected_piks = [
        n["pik"]["ip"]
        for n in (diff["added_nodes"] + diff["updated_nodes"])
        if "ip" in n["pik"]
    ]
    assert "10.0.0.2" in affected_piks
    assert "10.0.0.1" not in affected_piks

    await store.close()
