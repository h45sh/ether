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

    budget = getattr(args, "budget", None)
    max_tokens = int(budget if budget is not None else getattr(args, "max_tokens", 4000))
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


async def handle_telemetry_health(args: Any, context: CliContext) -> int:
    """Collect runtime diagnostics and emit JSON or Prometheus text metrics."""
    from ether.core.diagnostics import DiagnosticEngine

    engine = DiagnosticEngine(db_path=context.db_path, tools_dir=context.tools_dir)
    metrics = await engine.collect_runtime_metrics()

    if getattr(args, "prometheus", False):
        prom_text = engine.to_prometheus_text(metrics)
        print(prom_text, end="")
        return EXIT_SUCCESS

    if context.is_json:
        print_json(metrics)
    else:
        print("[+] Ether Telemetry Substrate Health")
        print(
            f"    Open FDs:               {metrics.get('open_fds')} (soft max: {metrics.get('max_fds', {}).get('soft')})"
        )
        print(
            f"    Resident Memory (RSS):  {metrics.get('resident_memory_bytes', 0) / (1024 * 1024):.2f} MB"
        )
        print(
            f"    Event Loop Latency:     {metrics.get('event_loop_lag_seconds', 0.0) * 1000:.3f} ms"
        )
        print(f"    Active Workers:         {metrics.get('active_workers', 0)}")
        print(f"    Queue Depth:            {metrics.get('queue_depth', 0)}")

    return EXIT_SUCCESS
