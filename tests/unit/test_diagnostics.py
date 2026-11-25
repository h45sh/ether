"""Unit tests for DiagnosticEngine."""

import pytest

from ether.core.diagnostics import (
    INSTALLATION_HINTS,
    DiagnosticCheck,
    DiagnosticEngine,
    DiagnosticReport,
)


@pytest.mark.asyncio
async def test_diagnostic_engine_run(tmp_path):
    """Verify that DiagnosticEngine runs complete audit suite against isolated database."""
    db_file = str(tmp_path / "diag_test.db")
    engine = DiagnosticEngine(db_path=db_file)

    report = await engine.run()

    assert isinstance(report, DiagnosticReport)
    assert report.system_info["python_version"] is not None
    assert "platform" in report.system_info
    assert report.tool_counts["total"] > 0

    # Checks should contain System, Logging, Database, and Tools
    categories = {c.category for c in report.checks}
    assert "System" in categories
    assert "Logging" in categories
    assert "Database" in categories
    assert "Tools" in categories

    # Database integrity check must have passed
    db_check = next(c for c in report.checks if c.name == "SQLite Integrity")
    assert db_check.status == "ok"


def test_diagnostic_report_summary_and_serialization():
    """Verify report dictionary serialization and status counts."""
    report = DiagnosticReport(
        healthy=True,
        checks=[
            DiagnosticCheck(name="C1", category="Test", status="ok", message="pass"),
            DiagnosticCheck(
                name="C2", category="Test", status="warning", message="warn", remedy="fix it"
            ),
            DiagnosticCheck(name="C3", category="Test", status="error", message="fail"),
        ],
    )

    data = report.to_dict()
    assert data["healthy"] is True
    assert len(data["checks"]) == 3

    summary = report.summary()
    assert summary["ok"] == 1
    assert summary["warning"] == 1
    assert summary["error"] == 1


def test_format_terminal_report():
    """Verify terminal report rendering formatting."""
    report = DiagnosticReport(
        healthy=False,
        checks=[
            DiagnosticCheck(
                name="Tool: nmap",
                category="Tools",
                status="info",
                message="not found",
                remedy=INSTALLATION_HINTS["nmap"],
            ),
            DiagnosticCheck(
                name="DB", category="Database", status="error", message="bad db", remedy="repair it"
            ),
        ],
    )

    output = DiagnosticEngine.format_terminal_report(report)
    assert "Ether System & Environmental Diagnostic Report" in output
    assert "[Tools]" in output
    assert "Remedy:" in output
    assert "UNHEALTHY" in output


@pytest.mark.asyncio
async def test_diagnostic_engine_runtime_metrics():
    """Verify substrate telemetry metrics collection."""
    engine = DiagnosticEngine()
    metrics = await engine.collect_runtime_metrics()

    assert "open_fds" in metrics
    assert "resident_memory_bytes" in metrics
    assert "event_loop_lag_seconds" in metrics
    assert "max_fds" in metrics
    assert "soft" in metrics["max_fds"]
    assert metrics["open_fds"] >= 0 or metrics["open_fds"] == -1
    assert metrics["resident_memory_bytes"] > 0
    assert metrics["event_loop_lag_seconds"] >= 0.0


def test_diagnostic_engine_prometheus_exporter():
    """Verify Prometheus text format compliance."""
    engine = DiagnosticEngine()
    custom_metrics = {
        "open_fds": 42,
        "max_fds": {"soft": 1024, "hard": 4096},
        "resident_memory_bytes": 10485760,
        "event_loop_lag_seconds": 0.0015,
        "active_workers": 2,
        "queue_depth": 5,
        "subprocess_latencies": {"p50": 0.05, "p90": 0.12, "p99": 0.35},
    }
    prom_text = engine.to_prometheus_text(custom_metrics)

    assert "ether_process_open_fds 42" in prom_text
    assert "ether_process_max_fds 1024" in prom_text
    assert "ether_process_resident_memory_bytes 10485760" in prom_text
    assert "ether_event_loop_lag_seconds 0.001500" in prom_text
    assert "ether_active_workers 2" in prom_text
    assert "ether_queue_depth 5" in prom_text
    assert 'ether_subprocess_duration_seconds{quantile="0.5"} 0.05' in prom_text
    assert 'ether_subprocess_duration_seconds{quantile="0.9"} 0.12' in prom_text
    assert 'ether_subprocess_duration_seconds{quantile="0.99"} 0.35' in prom_text
    assert "# TYPE ether_subprocess_duration_seconds summary" in prom_text


@pytest.mark.asyncio
async def test_cli_telemetry_health(tmp_path, capsys):
    """Verify CLI 'telemetry health' command execution with json and prometheus flags."""
    from argparse import Namespace

    from ether.cli.commands.telemetry import handle_telemetry_health
    from ether.cli.context import CliContext
    from ether.gateway.gate import GatePolicy

    db_file = str(tmp_path / "test.db")
    ctx = CliContext(
        data_dir=str(tmp_path),
        db_path=db_file,
        tools_dir=None,
        is_json=True,
        verbose=False,
        policy=GatePolicy.SAFE,
    )

    args = Namespace(prometheus=False)
    exit_code = await handle_telemetry_health(args, ctx)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert '"resident_memory_bytes"' in captured.out

    # Test Prometheus format
    args_prom = Namespace(prometheus=True)
    exit_code = await handle_telemetry_health(args_prom, ctx)
    assert exit_code == 0
    captured_prom = capsys.readouterr()
    assert "ether_process_resident_memory_bytes" in captured_prom.out


def test_diagnostic_engine_check_tools_uses_meta_binary_and_coroutine(tmp_path):
    """Verify _check_tools reads manifest.meta.binary and handles execution_tier == 'coroutine'."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    coro_manifest = SimpleNamespace(
        meta=SimpleNamespace(
            name="tls_probe",
            description="TLS probe",
            one_line_summary="",
            category="TLS",
            categories=["tls"],
            binary="tls_probe",
            execution_tier="coroutine",
        ),
        input={"accepts": ["network.host"], "target_types": ["ip"]},
        output={"produces": ["network.service"]},
    )
    coro_adapter = MagicMock()
    coro_adapter.validate_install.return_value = True

    bin_manifest = SimpleNamespace(
        meta=SimpleNamespace(
            name="netexec",
            description="NetExec",
            one_line_summary="",
            category="Network",
            categories=["network"],
            binary="nxc",
            execution_tier="subprocess",
        ),
        input={"accepts": ["network.host"], "target_types": ["ip"]},
        output={"produces": ["network.service"]},
    )
    bin_adapter = MagicMock()
    bin_adapter.validate_install.return_value = True

    mock_registry = MagicMock()
    mock_registry.list_tools.return_value = ["tls_probe", "netexec"]
    mock_registry.get_tool.side_effect = lambda n: {
        "tls_probe": {"manifest": coro_manifest, "adapter": coro_adapter},
        "netexec": {"manifest": bin_manifest, "adapter": bin_adapter},
    }.get(n)
    mock_registry.list_tool_summaries.return_value = [
        {
            "name": "tls_probe",
            "binary": "tls_probe",
            "execution_tier": "coroutine",
            "installed": True,
        },
        {
            "name": "netexec",
            "binary": "nxc",
            "execution_tier": "subprocess",
            "installed": True,
        },
    ]

    engine = DiagnosticEngine(db_path=str(tmp_path / "d.db"), registry=mock_registry)
    report = DiagnosticReport()
    with patch(
        "ether.core.diagnostics.shutil.which",
        side_effect=lambda b: "/usr/bin/nxc" if b == "nxc" else None,
    ):
        engine._check_tools(report)

    checks_by_name = {c.name: c for c in report.checks}
    assert checks_by_name["Tool: tls_probe"].status == "ok"
    assert "coroutine" in checks_by_name["Tool: tls_probe"].message.lower()
    assert checks_by_name["Tool: netexec"].status == "ok"
    assert "/usr/bin/nxc" in checks_by_name["Tool: netexec"].message
