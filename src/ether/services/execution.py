"""Deep domain service coordinating tool execution, zero-token diffing, and output sanitization."""

from __future__ import annotations

import asyncio
import shlex
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union
from uuid import UUID

from ether.common import sanitize_untrusted_output
from ether.common.exceptions import ExecutionErrorCategory
from ether.core.pipeline import PipelineEngine, PipelineParser
from ether.core.session import (
    ExecutionChunk,
    ExecutionCompleted,
    ExecutionFailed,
    ExecutionSession,
    ExecutionStarted,
)
from ether.graph.telemetry import GraphTelemetryCompiler
from ether.schemas.power import ActionRequest, JobStatusEnum

if TYPE_CHECKING:
    from ether.gateway.gate import ActionGateway
    from ether.graph.store import GraphStore


class SupervisedExecutionService:
    """Unified application facade executing security actions with automatic state diffing,

    prompt injection neutralization, and forensic audit recording.
    Used symmetrically by both the Headless CLI ('ether run') and native MCP ('execute_tool').
    """

    def __init__(
        self,
        gateway: ActionGateway,
        store: GraphStore,
        execution_session: Optional[ExecutionSession] = None,
    ):
        self.gateway = gateway
        self.store = store
        self.exec_sess = execution_session or gateway.create_session()

    async def execute_tool(
        self,
        tool_name: str,
        target: str,
        arguments: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        timeout_seconds: Union[int, float] = 120,
        include_raw: bool = False,
        chunk_callback: Optional[Callable[[str], None]] = None,
        profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a security tool under process supervision, preflight verification, and telemetry diffing."""
        # 1. Resolve investigation session
        if not session_id:
            _, sess_id = await self.store.get_or_create_default_session()
            session_id = sess_id

        # 2. Verify tool registration
        registry = self.gateway.registry
        tool_entry = registry.get_tool(tool_name)
        if not tool_entry:
            return {
                "is_error": True,
                "error_category": ExecutionErrorCategory.BINARY_MISSING.value,
                "exit_code": 127,
                "stderr_snippet": f"Tool '{tool_name}' is not registered in Ether arsenal.",
                "error": "ToolNotFound",
                "message": f"Tool '{tool_name}' is not registered in Ether arsenal.",
                "remediation": "Check registered tools via 'ether tool search' or 'ether tool list'.",
            }

        # 3. Resolve profile + normalize flags
        args_dict = arguments or {}
        resolved_profile = profile or args_dict.get("profile")
        profile_flags: List[str] = []
        if resolved_profile:
            manifest = tool_entry.get("manifest")
            profiles = getattr(manifest, "profiles", None) or {}
            tier = getattr(getattr(manifest, "meta", None), "execution_tier", "subprocess")
            if resolved_profile in profiles:
                profile_flags = [str(f) for f in profiles[resolved_profile]]
            elif tier == "coroutine" or not profiles:
                profile_flags = []
            else:
                avail = ", ".join(sorted(profiles.keys()))
                return {
                    "is_error": True,
                    "error_category": ExecutionErrorCategory.INVALID_ARGUMENT.value
                    if hasattr(ExecutionErrorCategory, "INVALID_ARGUMENT")
                    else "invalid_argument",
                    "exit_code": 2,
                    "stderr_snippet": f"Unknown profile '{resolved_profile}' for '{tool_name}'. Available: {avail}",
                    "error": "UnknownProfile",
                    "message": f"Unknown profile '{resolved_profile}' for '{tool_name}'. Available: {avail}",
                    "remediation": f"Use one of: {avail}",
                }

        raw_flags = args_dict.get("flags")
        if raw_flags is None:
            raw_flags = args_dict.get("raw_flags", [])
        if isinstance(raw_flags, list):
            explicit_flags = [str(f) for f in raw_flags]
        elif isinstance(raw_flags, str) and raw_flags.strip():
            explicit_flags = shlex.split(raw_flags.strip())
        else:
            explicit_flags = []

        flags_list = profile_flags + explicit_flags
        flags_str = " ".join(flags_list)

        # 4. Preflight verification gate
        report = self.gateway.preflight_verify(tool_name=tool_name, target=target, flags=flags_str)
        if not report.is_valid:
            return self._format_preflight_rejection(
                report=report,
                message=f"Execution of '{tool_name}' against '{target}' rejected by policy {self.gateway.policy.value}.",
            )

        warnings_list = [
            {"category": w.category, "title": w.title, "description": w.description}
            for w in report.warnings
        ]

        # 5. Target finding inference and persistence
        target_finding = self.gateway.infer_target_finding(target)
        target_node_id = await self.store.upsert_finding(session_id, target_finding)

        action = ActionRequest(
            session_id=UUID(session_id),
            tool_name=tool_name,
            target_entity_id=target_node_id,
            params={"target": target, "flags": flags_list},
            timeout_seconds=float(timeout_seconds) if timeout_seconds is not None else None,
        )

        try:
            action_id = await self.exec_sess.dispatch(action)
        except Exception as e:
            cat = (
                ExecutionErrorCategory.BINARY_MISSING.value
                if isinstance(e, FileNotFoundError)
                else ExecutionErrorCategory.NON_ZERO_EXIT.value
            )
            return {
                "is_error": True,
                "error_category": cat,
                "exit_code": 127 if isinstance(e, FileNotFoundError) else 1,
                "stderr_snippet": str(e),
                "error": type(e).__name__,
                "message": str(e),
                "remediation": "Verify tool arguments and input schema requirements.",
            }

        # 6. Stream and await execution events (zero-copy: ExecutionSession owns the bounded ring buffer)
        async def _await_events() -> tuple[int, Optional[str]]:
            exit_code = 0
            err_msg = None
            async for event in self.exec_sess.subscribe(action_id):
                if isinstance(event, ExecutionStarted):
                    pass
                elif isinstance(event, ExecutionChunk):
                    if chunk_callback is not None:
                        try:
                            chunk_callback(event.text)
                        except Exception:
                            pass
                elif isinstance(event, ExecutionCompleted):
                    ev_exit = getattr(event, "exit_code", None)
                    if ev_exit is not None and ev_exit != 0:
                        exit_code = ev_exit
                        err_msg = err_msg or f"Process exited with code {ev_exit}"
                    elif (
                        getattr(event, "status", None) == JobStatusEnum.FAILED
                        or getattr(getattr(event, "status", None), "value", None) == "failed"
                    ):
                        exit_code = 1
                        err_msg = err_msg or "Execution failed with status FAILED"
                    else:
                        exit_code = 0
                elif isinstance(event, ExecutionFailed):
                    exit_code = getattr(event, "exit_code", None) or 1
                    err_msg = event.error or f"Process exited with code {exit_code}"
            return exit_code, err_msg

        try:
            exit_code, err_msg = await asyncio.wait_for(_await_events(), timeout=timeout_seconds)
            compiler = GraphTelemetryCompiler(
                self.store, session_id, execution_session=self.exec_sess
            )
            diff = await compiler.compute_graph_diff(action_id=str(action_id))
            raw_text = "".join(self.exec_sess.get_output_history(action_id))
            is_err = (exit_code != 0) or (err_msg is not None)

            result: Dict[str, Any] = {
                "status": "completed" if not is_err else "failed",
                "action_id": str(action_id),
                "session_id": session_id,
                "tool_name": tool_name,
                "exit_code": exit_code,
                "error": err_msg,
                "diff": diff,
                "findings_count": diff.get("total_delta_count", 0),
                "status_breakdown": diff.get("status_breakdown", {}),
                "warnings": warnings_list,
                "summary": f"Execution of {tool_name} completed with {diff['total_delta_count']} new or updated findings.",
            }

            if is_err:
                result["is_error"] = True
                combined = f"{err_msg or ''} {raw_text}".lower()
                if any(
                    x in combined
                    for x in ("timed out", "timeout", "deadline exceeded", "command timed out")
                ):
                    cat = ExecutionErrorCategory.COMMAND_TIMEOUT.value
                elif any(
                    x in combined
                    for x in (
                        "connection refused",
                        "no route to host",
                        "host unreachable",
                        "network unreachable",
                        "name or service not known",
                        "could not resolve host",
                        "target unreachable",
                    )
                ):
                    cat = ExecutionErrorCategory.TARGET_UNREACHABLE.value
                elif any(
                    x in combined
                    for x in (
                        "command not found",
                        "not found",
                        "no such file or directory",
                        "cannot find binary",
                    )
                ):
                    cat = ExecutionErrorCategory.BINARY_MISSING.value
                elif any(
                    x in combined
                    for x in (
                        "scope blocked",
                        "policy violation",
                        "ssrf blocked",
                        "permission denied",
                    )
                ):
                    cat = ExecutionErrorCategory.SCOPE_BLOCKED.value
                else:
                    cat = ExecutionErrorCategory.NON_ZERO_EXIT.value

                result["error_category"] = cat
                snippet = err_msg or (
                    raw_text[-500:].strip()
                    if raw_text
                    else "Execution failed with non-zero exit code."
                )
                result["stderr_snippet"] = snippet
            else:
                result["is_error"] = False

            if include_raw:
                result["raw_stdout"] = raw_text
                result["untrusted_output"] = sanitize_untrusted_output(raw_text)

            return result

        except asyncio.TimeoutError:
            return {
                "status": "running",
                "action_id": str(action_id),
                "session_id": session_id,
                "tool_name": tool_name,
                "is_error": False,
                "message": f"Execution exceeded {timeout_seconds}s deadline and is continuing in background. Use get_diff(action_id='{action_id}') to inspect findings.",
                "tokens_consumed": 0,
            }

    def _format_preflight_rejection(self, report: Any, message: str) -> Dict[str, Any]:
        """Format a failed PreflightReport into a structured error dictionary."""
        error_list = [
            {
                "title": e.title,
                "description": e.description,
                "remediation": e.remediation_hint,
                "category": e.category,
            }
            for e in report.errors
        ]
        return {
            "is_error": True,
            "error_category": ExecutionErrorCategory.SCOPE_BLOCKED.value,
            "exit_code": 1,
            "stderr_snippet": "; ".join(e["description"] for e in error_list),
            "error": "PreflightGateRejected",
            "message": message,
            "errors": error_list,
            "warnings": [
                {"category": w.category, "title": w.title, "description": w.description}
                for w in report.warnings
            ],
            "remediation": error_list[0]["remediation"]
            if error_list
            else "Adjust target scope or policy.",
        }

    async def execute_pipeline(
        self,
        expression: str,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Parse, preflight-verify, and execute a declarative tool pipeline expression."""
        if not session_id:
            _, sess_id = await self.store.get_or_create_default_session()
            session_id = sess_id

        try:
            stages = PipelineParser.parse(expression, self.gateway.registry)
        except ValueError as e:
            return {"is_error": True, "error": "InvalidPipeline", "message": str(e)}

        if not stages:
            return {
                "is_error": True,
                "error": "EmptyPipeline",
                "message": "No pipeline stages found.",
            }

        first_stage = stages[0]
        raw_target = first_stage.params.get("target") or "127.0.0.1"
        report = self.gateway.preflight_verify(
            tool_name=first_stage.tool_name, target=raw_target, flags=""
        )
        if not report.is_valid:
            return self._format_preflight_rejection(
                report=report,
                message=f"Pipeline stage '{first_stage.tool_name}' against '{raw_target}' rejected by policy {self.gateway.policy.value}.",
            )

        engine = PipelineEngine(
            self.gateway.registry,
            store=self.store,
            command_runner=getattr(self.exec_sess, "command_runner", None),
        )
        collected: List[Dict[str, Any]] = []
        try:
            async for finding in engine.execute_pipeline(
                expression=expression,
                session_id=session_id,
                policy=self.gateway.policy.value,
            ):
                collected.append(
                    {
                        "schema_type": finding.schema_type,
                        "pik": finding.pik,
                        "data": finding.data,
                    }
                )
        except Exception as e:
            return {
                "is_error": True,
                "error": type(e).__name__,
                "message": f"Pipeline execution failed: {e}",
            }

        return {
            "is_error": False,
            "session_id": session_id,
            "expression": expression,
            "stages": [s.tool_name for s in stages],
            "total_findings": len(collected),
            "findings": collected,
        }
