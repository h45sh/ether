"""CLI handler for declarative tool pipeline execution."""

from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json
from ether.core.pipeline import PipelineEngine, PipelineParser
from ether.gateway.gate import ActionGateway, GatePolicy
from ether.registry.registry import ToolRegistry


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

    try:
        stages = PipelineParser.parse(expression, registry)
    except ValueError as e:
        print_error(f"Invalid pipeline expression: {e}")
        return EXIT_RUNTIME_ERROR

    if not stages:
        print_error("Pipeline expression produced no stages.")
        return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        policy = (
            GatePolicy(context.policy)
            if not isinstance(context.policy, GatePolicy)
            else context.policy
        )
        gw = ActionGateway(registry=registry, store=store, policy=policy)
        first_stage = stages[0]
        raw_target = first_stage.params.get("target") or "127.0.0.1"
        report = gw.preflight_verify(tool_name=first_stage.tool_name, target=raw_target, flags="")
        if not report.is_valid:
            msg = "; ".join(e.description for e in report.errors)
            print_error(f"Preflight policy rejected pipeline target '{raw_target}': {msg}")
            return EXIT_RUNTIME_ERROR

        engine = PipelineEngine(registry=registry, store=store)
        findings = []
        try:
            async for finding in engine.execute_pipeline(
                expression=expression,
                session_id=session_id,
                policy=policy.value,
            ):
                if session_id:
                    await store.upsert_finding(session_id, finding)
                findings.append(finding.model_dump(mode="json"))
        except Exception as e:
            print_error(f"Pipeline execution failed: {e}")
            return EXIT_RUNTIME_ERROR

    print_json({"expression": expression, "count": len(findings), "findings": findings})
    return EXIT_SUCCESS
