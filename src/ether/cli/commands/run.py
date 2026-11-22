"""Handler for 'ether run <tool> <target>' command."""

import ipaddress
import shlex
import sys
from typing import Any, List
from uuid import UUID

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json
from ether.core.session import (
    ExecutionChunk,
    ExecutionCompleted,
    ExecutionFailed,
    ExecutionStarted,
)
from ether.gateway.gate import ActionGateway
from ether.schemas.base import BaseFinding
from ether.schemas.dns import DomainInfo
from ether.schemas.network import NetworkHost
from ether.schemas.power import ActionRequest
from ether.schemas.web import WebEndpoint


def _infer_target_finding(target: str) -> BaseFinding:
    """Infer the typed BaseFinding entity from a raw CLI target string."""
    # Check IP
    try:
        ipaddress.ip_address(target)
        return NetworkHost.create(ip=target)
    except ValueError:
        pass

    # Check Web URL
    if target.startswith("http://") or target.startswith("https://"):
        return WebEndpoint.create(url=target)

    # Check CIDR
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return BaseFinding(
                schema_type="network.netblock", pik={"cidr": target}, data={"cidr": target}
            )
        except ValueError:
            pass

    # Default to DomainInfo
    return DomainInfo.create(domain=target)


async def handle_run(args: Any, context: CliContext) -> int:
    """Execute a tool action through the preflight gate, gateway, and execution session."""
    tool_name = getattr(args, "tool", None)
    target = getattr(args, "target", None)
    raw_flags = getattr(args, "flags", None) or []
    flags: List[str] = []
    for f in raw_flags:
        flags.extend(shlex.split(f) if isinstance(f, str) else [str(f)])

    if not tool_name or not target:
        print_error(
            "Both tool and target are required. Usage: ether run <tool> <target> [flags...]"
        )
        return EXIT_RUNTIME_ERROR

    registry = context.get_registry()
    if not registry.get_tool(tool_name):
        print_error(f"Tool '{tool_name}' is not registered.")
        return EXIT_RUNTIME_ERROR

    # 1. Preflight Verification Gate via ActionGateway
    gateway = ActionGateway(registry=registry, policy=context.policy)
    flags_str = " ".join(flags)
    report = gateway.preflight_verify(tool_name=tool_name, target=target, flags=flags_str)

    if not report.is_valid:
        print_error(f"Preflight validation failed for '{tool_name}':")
        for err in report.errors:
            print(f"  [-] {err.code}: {err.message}", file=sys.stderr)
            if err.remedy:
                print(f"      Remedy: {err.remedy}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    if report.has_warnings and not context.is_json:
        for warn in report.warnings:
            print(f"  [!] Warning ({warn.code}): {warn.message}", file=sys.stderr)

    # 2. Database & Target Finding Setup
    async with context.open_store() as store:
        gateway.store = store
        session_id = getattr(args, "session_id", None)
        if not session_id:
            _, sess_id = await store.get_or_create_learning_sandbox()
            session_id = sess_id

        target_finding = _infer_target_finding(target)
        target_node_id = await store.upsert_finding(session_id, target_finding)

        # 3. Execution Session Setup via Gateway
        session = gateway.create_session()

        action = ActionRequest(
            session_id=UUID(session_id),
            tool_name=tool_name,
            target_entity_id=target_node_id,
            params={"target": target, "flags": flags},
        )

        if not context.is_json:
            print(f"[*] Dispatching {tool_name} against {target} (Session: {session_id[:8]}...)")

        # 4. Dispatch and Stream Events
        action_id = await session.dispatch(action)
        exit_code = EXIT_SUCCESS

        async for event in session.subscribe(action_id):
            if isinstance(event, ExecutionStarted):
                if not context.is_json and context.verbose:
                    print(f"[*] Command: {' '.join(event.command)}")
            elif isinstance(event, ExecutionChunk):
                if not context.is_json:
                    sys.stdout.write(event.text)
                    sys.stdout.flush()
            elif isinstance(event, ExecutionFailed):
                print_error(f"Execution failed: {event.error}")
                exit_code = EXIT_RUNTIME_ERROR
            elif isinstance(event, ExecutionCompleted):
                if not context.is_json:
                    print(
                        f"\n[*] Execution finished (Status: {event.status.value}, Findings: {event.findings_count}, Duration: {event.duration_seconds:.2f}s)"
                    )
                elif context.is_json:
                    print_json(
                        {
                            "action_id": str(action_id),
                            "session_id": str(session_id),
                            "tool_name": tool_name,
                            "status": event.status.value,
                            "findings_count": event.findings_count,
                            "duration_seconds": event.duration_seconds,
                        }
                    )

        await session.shutdown()
        return exit_code
