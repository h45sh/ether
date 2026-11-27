"""Handlers for 'ether drift' subcommands."""

from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, EXIT_USAGE_ERROR, CliContext
from ether.cli.formatters import print_error, print_json, print_table
from ether.drift.engine import audit_drift, export_baseline


async def handle_drift_export_baseline(args: Any, context: CliContext) -> int:
    """Export an investigation session graph as a ground-truth baseline JSON file."""
    session_id = getattr(args, "session_id", None)
    out_path = getattr(args, "out", None)

    if not session_id:
        print_error("A session_id is required to export an architectural baseline.")
        return EXIT_USAGE_ERROR

    try:
        async with context.open_store() as store:
            baseline = await export_baseline(store, session_id, out_path=out_path)

        if context.is_json:
            print_json(baseline)
        else:
            node_count = len(baseline.get("nodes", []))
            target_desc = f" to '{out_path}'" if out_path else ""
            print(
                f"[+] Exported baseline with {node_count} nodes for session '{session_id}'{target_desc}"
            )
        return EXIT_SUCCESS
    except Exception as e:
        print_error(f"Failed to export baseline: {e}")
        return EXIT_RUNTIME_ERROR


async def handle_drift_audit(args: Any, context: CliContext) -> int:
    """Audit an observed investigation session against an architectural baseline."""
    session_id = getattr(args, "session_id", None)
    baseline_path = getattr(args, "baseline", None)
    mode = getattr(args, "mode", "topology")
    record = getattr(args, "record", False)

    if not session_id or not baseline_path:
        print_error("Both session_id and --baseline file are required for drift audit.")
        return EXIT_USAGE_ERROR

    try:
        async with context.open_store() as store:
            report = await audit_drift(
                store,
                session_id,
                baseline=baseline_path,
                mode=mode,
                record_findings=record,
            )

        if context.is_json:
            print_json(report.to_dict())
            return EXIT_SUCCESS

        print(f"[+] Architectural Drift Audit for Session: {session_id}")
        print(
            f"    Mode: {report.mode} | Drift Score: {report.drift_score:.4f} (0.0 = perfect match, 1.0 = total divergence)"
        )
        print(
            f"    Summary: {report.summary['matching_count']} matching, {report.summary['missing_count']} missing, {report.summary['unexpected_count']} unexpected"
        )

        if report.discrepancies:
            headers = ["TYPE", "TARGET", "SEVERITY", "DESCRIPTION"]
            rows = [
                [
                    d.pik.get("discrepancy_type", ""),
                    d.pik.get("target_key", ""),
                    d.data.get("severity", "medium"),
                    d.data.get("description", ""),
                ]
                for d in report.discrepancies
            ]
            print("\nDiscrepancies:")
            print_table(headers, rows)
        else:
            print("[+] Zero discrepancies detected. Observed architecture conforms to baseline.")

        if record:
            print(
                f"[+] Recorded {len(report.discrepancies)} audit.drift findings to session graph."
            )

        return EXIT_SUCCESS
    except Exception as e:
        print_error(f"Failed to execute drift audit: {e}")
        return EXIT_RUNTIME_ERROR
