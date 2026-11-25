"""Handler for 'ether run <tool> <target>' command."""

import shlex
import sys
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json
from ether.gateway.gate import ActionGateway
from ether.services.execution import SupervisedExecutionService


async def handle_run(args: Any, context: CliContext) -> int:
    """Execute a tool action through the unified SupervisedExecutionService."""
    tool_name = getattr(args, "tool", None)
    target = getattr(args, "target", None)
    raw_flags = getattr(args, "flags", None) or ""
    if isinstance(raw_flags, str):
        flags = shlex.split(raw_flags.strip()) if raw_flags.strip() else []
        flags_str = raw_flags.strip()
    else:
        flags = []
        for f in raw_flags:
            flags.extend(shlex.split(f) if isinstance(f, str) else [str(f)])
        flags_str = " ".join(flags)

    if not tool_name or not target:
        print_error(
            "Both tool and target are required. Usage: ether run <tool> <target> [flags...]"
        )
        return EXIT_RUNTIME_ERROR

    registry = context.get_registry()
    if not registry.get_tool(tool_name):
        print_error(f"Tool '{tool_name}' is not registered.")
        return EXIT_RUNTIME_ERROR

    gateway = ActionGateway(registry=registry, policy=context.policy)

    async with context.open_store() as store:
        gateway.store = store
        session_id = getattr(args, "session_id", None)
        service = SupervisedExecutionService(gateway=gateway, store=store)

        if not context.is_json:
            print(f"[*] Dispatching {tool_name} against {target} (Policy: {context.policy.value})")

        def _chunk_cb(text: str) -> None:
            if not context.is_json:
                sys.stdout.write(text)
                sys.stdout.flush()

        result = await service.execute_tool(
            tool_name=tool_name,
            target=target,
            arguments={"flags": flags, "raw_flags": flags_str},
            session_id=session_id,
            include_raw=True,
            chunk_callback=_chunk_cb,
        )

        if result.get("is_error"):
            if result.get("error") == "PreflightGateRejected" and result.get("errors"):
                print_error(f"Preflight validation failed for '{tool_name}':")
                for err in result["errors"]:
                    cat = err.get("category", "preflight")
                    title = err.get("title", "Preflight Error")
                    desc = err.get("description", "")
                    print(f"  [-] [{cat}] {title}: {desc}", file=sys.stderr)
                    if err.get("remediation"):
                        print(f"      Remedy: {err['remediation']}", file=sys.stderr)
            else:
                print_error(
                    result.get("stderr_snippet") or result.get("message") or "Execution failed."
                )
                if result.get("remediation") and not context.is_json:
                    print(f"      Remedy: {result['remediation']}", file=sys.stderr)
            return EXIT_RUNTIME_ERROR

        if not context.is_json:
            findings_count = result.get("findings_count", 0)
            status = result.get("status", "completed")
            print(f"\n[*] Execution finished (Status: {status}, Findings: {findings_count})")
        else:
            print_json(
                {
                    "action_id": result.get("action_id"),
                    "session_id": result.get("session_id"),
                    "tool_name": tool_name,
                    "status": result.get("status"),
                    "findings_count": result.get("findings_count", 0),
                    "diff": result.get("diff"),
                }
            )

        return EXIT_SUCCESS
