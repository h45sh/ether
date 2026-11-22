"""Handlers for 'ether logs' subcommands."""

import os
from typing import Any

from ether import paths
from ether.cli.context import EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_json
from ether.common.logging import get_recent_crash_summary


def handle_logs(args: Any, context: CliContext) -> int:
    """Display system log records or recent crash reports."""
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
            print(crash["traceback"])
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
