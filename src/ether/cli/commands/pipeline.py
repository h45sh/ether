"""CLI handler for declarative tool pipeline execution."""

from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json
from ether.core.pipeline import PipelineEngine
from ether.registry.registry import ToolRegistry


async def handle_pipeline_run(args: Any, context: CliContext) -> int:
    """Execute declarative pipeline string and stream results."""
    expression = getattr(args, "expression", None)
    if not expression:
        print_error("Pipeline expression is required (e.g. 'subfinder | dnspython | http_probe').")
        return EXIT_RUNTIME_ERROR

    session_id = getattr(args, "session", None) or getattr(args, "session_id", None)
    registry = ToolRegistry(context.tools_dir)
    registry.load_tools()

    async with context.open_store() as store:
        engine = PipelineEngine(registry=registry, store=store)
        findings = []
        try:
            async for finding in engine.execute_pipeline(
                expression=expression,
                session_id=session_id,
                policy=context.policy,
            ):
                findings.append(finding.model_dump(mode="json"))
        except Exception as e:
            print_error(f"Pipeline execution failed: {e}")
            return EXIT_RUNTIME_ERROR

    print_json({"expression": expression, "count": len(findings), "findings": findings})
    return EXIT_SUCCESS
