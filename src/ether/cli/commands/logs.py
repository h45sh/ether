"""Handlers for 'ether logs' subcommands."""

import os
from typing import Any

from ether import paths
from ether.cli.context import EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_json
from ether.common.logging import get_recent_crash_summary
from ether.common.storage import StorageLifecycleManager


def handle_logs(args: Any, context: CliContext) -> int:
    """Display system log records, recent crash reports, or enforce log retention."""
    if getattr(args, "prune", False):
        logs_dir = paths.get_default_logs_dir(context.data_dir)
        max_disk_mb = int(getattr(args, "max_disk_mb", 1000))
        max_age_days = int(getattr(args, "max_age_days", 30))
        include_forensic = bool(getattr(args, "include_forensic", False))

        report = StorageLifecycleManager.enforce_retention_policy(
            logs_dir=logs_dir,
            max_disk_mb=max_disk_mb,
            max_age_days=max_age_days,
            include_forensic=include_forensic,
        )
        if context.is_json:
            print_json(report.to_dict())
        else:
            print("[+] Log Retention Policy Enforced:")
            print(f"    Scanned:    {report.total_scanned_bytes / (1024*1024):.2f} MB")
            print(f"    Compressed: {report.compressed_files} files")
            print(f"    Pruned:     {report.pruned_files} files")
            print(f"    Freed:      {report.freed_bytes / (1024*1024):.2f} MB")
            print(f"    Protected:  {report.skipped_forensic_files} forensic logs preserved")
            print(f"    Remaining:  {report.remaining_bytes / (1024*1024):.2f} MB")
        return EXIT_SUCCESS

    show_crashes = bool(getattr(args, "crashes", False))
    lines_limit = int(getattr(args, "limit", 50))

    if show_crashes:
        crash = get_recent_crash_summary(context.data_dir, max_lines=lines_limit)
        if context.is_json:
            print_json(crash or {})
        elif crash:
            print(f"Recent Crash [{crash['timestamp']}]:")
            print(f"Summary: {crash['summary']}")
            print("\nTraceback:")
            print(crash["block"])
        else:
            print("[+] No unhandled crashes recorded in system log.")
        return EXIT_SUCCESS

    log_path = paths.get_system_log_path(context.data_dir)
    if not os.path.exists(log_path):
        print(f"[+] No system log file at '{log_path}'.")
        return EXIT_SUCCESS

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
        tail = all_lines[-lines_limit:]

    if context.is_json:
        print_json({"log_file": log_path, "lines": [line.rstrip() for line in tail]})
    else:
        for line in tail:
            print(line, end="")

    return EXIT_SUCCESS
