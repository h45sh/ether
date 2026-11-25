"""Unit tests for 'ether drift' CLI subcommands and parameter symmetry."""

import json
from pathlib import Path

import pytest

from ether.cli.router import main
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.asyncio
async def test_cli_drift_export_and_audit(tmp_path: Path, capsys):
    """Verify 'ether drift export-baseline' and 'ether drift audit' via CLI."""
    db_file = str(tmp_path / "cli_drift.db")
    baseline_file = str(tmp_path / "cli_baseline.json")

    store = GraphStore(db_file)
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_workspace_session("DriftWS", "CliDriftSess")

    host = NetworkHost.create(ip="192.168.1.1", hostname="router.lan")
    svc = NetworkService.create(host_ip="192.168.1.1", port=80, protocol="tcp", service_name="http")
    await store.upsert_finding(sess_id, host)
    await store.upsert_finding(sess_id, svc)
    await store.close()

    # 1. Export baseline via CLI with positional args
    rc = main(["--db", db_file, "drift", "export-baseline", sess_id, "--out", baseline_file])
    assert rc == 0
    assert Path(baseline_file).exists()
    capsys.readouterr()  # Clear stdout buffer

    with open(baseline_file) as f:
        data = json.load(f)
    assert len(data["nodes"]) >= 2

    # 2. Audit same session (zero drift)
    rc = main(["--db", db_file, "drift", "audit", sess_id, "--baseline", baseline_file, "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    report_dict = json.loads(out)
    assert report_dict["drift_score"] == 0.0
    assert len(report_dict["discrepancies"]) == 0

    # 3. Parameter symmetry: test with --session option instead of positional
    rc = main(
        [
            "--db",
            db_file,
            "drift",
            "audit",
            "--session",
            sess_id,
            "--baseline",
            baseline_file,
            "--json",
        ]
    )
    assert rc == 0
