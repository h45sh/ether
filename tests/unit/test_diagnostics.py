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
