"""Headless terminal text styling and JSON formatting for Ether CLI."""

import json
import sys
from typing import Any, List


def print_json(data: Any) -> None:
    """Output machine-readable formatted JSON to stdout."""
    print(json.dumps(data, indent=2, default=str), file=sys.stdout)


def print_error(msg: str) -> None:
    """Output an error message to stderr."""
    print(f"[!] Error: {msg}", file=sys.stderr)


def print_status(msg: str, is_json: bool = False) -> None:
    """Output status/progress message to stderr if json mode, or stdout if terminal mode."""
    target = sys.stderr if is_json else sys.stdout
    print(msg, file=target)


class ConsoleProgress:
    """Progress and diagnostic reporter that routes to stderr in JSON mode to preserve clean stdout JSON."""

    def __init__(self, is_json: bool = False):
        self.is_json = is_json
        self.target = sys.stderr if is_json else sys.stdout

    def log(self, message: str) -> None:
        """Log diagnostic or progress message."""
        print(message, file=self.target)

    def write(self, text: str) -> None:
        """Write partial stream text."""
        self.target.write(text)
        self.target.flush()


def print_table(headers: List[str], rows: List[List[str]]) -> None:
    """Format and print a simple ASCII table to stdout."""
    if not headers:
        return

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            if idx < len(col_widths):
                col_widths[idx] = max(col_widths[idx], len(str(val)))

    # Format header
    header_str = "  ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers))
    sep_str = "  ".join("-" * col_widths[i] for i in range(len(headers)))
    sys.stdout.write(f"{header_str}\n")
    sys.stdout.write(f"{sep_str}\n")

    # Format rows
    for row in rows:
        row_str = "  ".join(f"{str(val):<{col_widths[i]}}" for i, val in enumerate(row))
        # CodeQL [py/cleartext-logging-sensitive-data] CLI terminal table output formatted for operator stdout
        sys.stdout.write(f"{row_str}\n")
    sys.stdout.flush()
