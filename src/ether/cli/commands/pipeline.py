"""CLI handler for declarative tool pipeline execution."""

from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json
from ether.gateway.gate import ActionGateway, GatePolicy
from ether.registry.registry import ToolRegistry
from ether.services.execution import SupervisedExecutionService


async def handle_pipeline_run(args: Any, context: CliContext) -> int:
    """Execute declarative pipeline string and stream results."""
    expression = getattr(args, "expression", None)
    if not expression:
        print_error(
            "Pipeline expression is required (e.g. 'subfinder(target=example.com) | dnspython | http_probe')."
        )
        return EXIT_RUNTIME_ERROR

    session_id = getattr(args, "session", None) or getattr(args, "session_id", None)
    registry = ToolRegistry(context.tools_dir)
    registry.load_tools()

    async with context.open_store() as store:
        policy = (
            GatePolicy(context.policy)
            if not isinstance(context.policy, GatePolicy)
            else context.policy
        )
        gw = ActionGateway(registry=registry, store=store, policy=policy)
        service = SupervisedExecutionService(gateway=gw, store=store)
        result = await service.execute_pipeline(expression=expression, session_id=session_id)

        if result.get("is_error"):
            print_error(result.get("message") or "Pipeline execution failed.")
            return EXIT_RUNTIME_ERROR

    print_json(
        {
            "expression": expression,
            "count": result["total_findings"],
            "findings": result["findings"],
        }
    )
    return EXIT_SUCCESS
