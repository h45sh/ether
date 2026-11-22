"""Handlers for 'ether telemetry' subcommands."""

from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json
from ether.graph.telemetry import GraphTelemetryCompiler


async def handle_telemetry_snapshot(args: Any, context: CliContext) -> int:
    """Compile token-budgeted agent telemetry snapshot for a session."""
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("session_id is required.")
        return EXIT_RUNTIME_ERROR

    max_tokens = int(getattr(args, "max_tokens", 4000))
    selected_entity_id = getattr(args, "entity_id", None)

    async with context.open_store() as store:
        compiler = GraphTelemetryCompiler(store, session_id)
        try:
            snapshot = await compiler.compile_telemetry_snapshot(
                selected_entity_id=selected_entity_id, max_tokens=max_tokens
            )
        except Exception as e:
            print_error(f"Failed to compile telemetry snapshot: {e}")
            return EXIT_RUNTIME_ERROR

    print_json(snapshot)
    return EXIT_SUCCESS


async def handle_telemetry_diff(args: Any, context: CliContext) -> int:
    """Compute zero-token semantic graph delta by action_id or since a baseline timestamp."""
    session_id = getattr(args, "session_id", None)
    baseline = getattr(args, "baseline", None)
    action_id = getattr(args, "action_id", None)
    if not session_id:
        print_error("session_id is required.")
        return EXIT_RUNTIME_ERROR
    if baseline is None and action_id is None:
        print_error("Either --action-id or --baseline timestamp is required.")
        return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        compiler = GraphTelemetryCompiler(store, session_id)
        diff = await compiler.compute_graph_diff(baseline_timestamp=baseline, action_id=action_id)

    print_json(diff)
    return EXIT_SUCCESS
