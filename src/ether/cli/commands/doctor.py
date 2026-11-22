"""Handler for 'ether doctor' diagnostic command."""

import sys
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_json
from ether.core.diagnostics import DiagnosticEngine


async def handle_doctor(args: Any, context: CliContext) -> int:
    """Run system, database, and tool diagnostics."""
    engine = DiagnosticEngine(db_path=context.db_path, tools_dir=context.tools_dir)
    report = await engine.run()

    if context.is_json:
        print_json(report.to_dict())
    else:
        print(DiagnosticEngine.format_terminal_report(report), file=sys.stdout)

    return EXIT_SUCCESS if report.healthy else EXIT_RUNTIME_ERROR
