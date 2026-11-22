"""Native Model Context Protocol (MCP) server implementation for Ether."""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from mcp.server.mcpserver import MCPServer

from ether.common import sanitize_untrusted_output
from ether.core.session import ExecutionCompleted, ExecutionFailed
from ether.gateway.gate import ActionGateway, GatePolicy
from ether.graph.store import GraphStore
from ether.graph.telemetry import GraphTelemetryCompiler
from ether.registry.registry import ToolRegistry
from ether.schemas.power import ActionRequest

logger = logging.getLogger(__name__)


def create_mcp_server(
    store: GraphStore,
    default_session_id: Optional[str] = None,
    policy: GatePolicy = GatePolicy.SAFE,
    gateway: Optional[ActionGateway] = None,
    registry: Optional[ToolRegistry] = None,
    execution_session: Optional[Any] = None,
) -> MCPServer:
    """Construct an MCP server instance exposing canonical security tools."""
    server = MCPServer("ether")

    reg = registry or ToolRegistry()
    if not reg.tools:
        reg.load_tools()
    gw = gateway or ActionGateway(registry=reg, store=store, policy=policy)
    gw.store = store
    exec_sess = execution_session or gw.create_session()

    async def _resolve_session(session_id: Optional[str]) -> str:
        """Resolve target session ID from argument, default, or active sandbox."""
        if session_id:
            return session_id
        if default_session_id:
            return default_session_id
        _, sess_id = await store.get_or_create_default_session()
        return sess_id

    @server.tool()
    async def query_graph(
        session_id: Optional[str] = None,
        schema_type: Optional[str] = None,
        limit: int = 100,
        include_stale: bool = False,
    ) -> str:
        """Query normalized cybersecurity findings and entities in the graph.

        Args:
            session_id: Target session ID (optional, defaults to active session).
            schema_type: Filter by schema type (e.g. 'network.host', 'network.service').
            limit: Maximum number of nodes to return (default: 100).
            include_stale: Whether to include decayed stale nodes (default: False).
        """
        sess_id = await _resolve_session(session_id)
        if schema_type:
            raw_nodes = await store.query(
                schema_type, session_id=sess_id, include_stale=include_stale
            )
        else:
            raw_nodes = await store.get_all_nodes(sess_id, include_stale=include_stale)

        limited_nodes: List[Dict[str, Any]] = []
        for n in raw_nodes[:limit]:
            try:
                pik_data = json.loads(n.get("pik_json") or "{}")
            except Exception:
                pik_data = {}
            try:
                finding_data = json.loads(n.get("data_json") or "{}")
            except Exception:
                finding_data = {}
            limited_nodes.append(
                {
                    "id": n["id"],
                    "schema_type": n["schema_type"],
                    "pik": pik_data,
                    "data": finding_data,
                    "status": n.get("status", "confirmed"),
                    "action_id": n.get("action_id"),
                    "created_at": n.get("created_at"),
                    "updated_at": n.get("updated_at"),
                }
            )

        return json.dumps(
            {
                "session_id": sess_id,
                "total": len(raw_nodes),
                "returned": len(limited_nodes),
                "nodes": limited_nodes,
            },
            indent=2,
        )

    @server.tool()
    async def inspect_entity(
        entity_id: str,
        session_id: Optional[str] = None,
    ) -> str:
        """Inspect detailed attributes, PIK, and relational edges for a specific entity node.

        Args:
            entity_id: Deterministic SHA-256 node ID.
            session_id: Target session ID (optional, defaults to active session).
        """
        sess_id = await _resolve_session(session_id)
        node = await store.get_node(sess_id, entity_id)
        if not node:
            return json.dumps({"error": "NotFound", "message": f"Entity '{entity_id}' not found."})

        # Fetch incident edges
        all_edges = await store.get_all_edges(sess_id)
        incident_edges = [
            e for e in all_edges if e["source_id"] == entity_id or e["target_id"] == entity_id
        ]

        try:
            pik_data = json.loads(node.get("pik_json") or "{}")
        except Exception:
            pik_data = {}
        try:
            finding_data = json.loads(node.get("data_json") or "{}")
        except Exception:
            finding_data = {}

        return json.dumps(
            {
                "session_id": sess_id,
                "entity": {
                    "id": node["id"],
                    "schema_type": node["schema_type"],
                    "pik": pik_data,
                    "data": finding_data,
                    "status": node.get("status", "confirmed"),
                    "action_id": node.get("action_id"),
                    "created_at": node.get("created_at"),
                    "updated_at": node.get("updated_at"),
                },
                "edges": incident_edges,
            },
            indent=2,
        )

    @server.tool()
    async def get_diff(
        session_id: Optional[str] = None,
        action_id: Optional[str] = None,
        baseline_timestamp: Optional[str] = None,
    ) -> str:
        """Retrieve zero-token set-theoretic delta envelope for an action or baseline timestamp.

        Args:
            session_id: Target session ID (optional, defaults to active session).
            action_id: Filter changes produced by a specific action execution run.
            baseline_timestamp: Filter changes produced since an ISO or epoch timestamp.
        """
        sess_id = await _resolve_session(session_id)
        compiler = GraphTelemetryCompiler(store, sess_id, execution_session=exec_sess)
        diff = await compiler.compute_graph_diff(
            baseline_timestamp=baseline_timestamp, action_id=action_id
        )
        return json.dumps(diff, indent=2)

    @server.tool()
    async def search_findings_semantic(
        query: str,
        session_id: Optional[str] = None,
        limit: int = 10,
        schema_type: Optional[str] = None,
        min_score: float = 0.0,
    ) -> str:
        """Search finding entities in the graph using natural language offline vector similarity.

        Args:
            query: Natural language search query (e.g. 'Apache HTTP Server path traversal').
            session_id: Target session ID (optional, defaults to active session).
            limit: Maximum findings to return (default: 10).
            schema_type: Optional filter by schema type (e.g. 'vulnerability.found').
            min_score: Minimum cosine similarity score between 0.0 and 1.0 (default: 0.0).
        """
        sess_id = await _resolve_session(session_id)
        results = await store.semantic_search(
            session_id=sess_id,
            query=query,
            limit=limit,
            schema_type=schema_type,
            min_score=min_score,
        )

        formatted_results = []
        for r in results:
            pik_data = r.get("pik")
            if not pik_data and r.get("pik_json"):
                try:
                    pik_data = json.loads(r["pik_json"])
                except Exception:
                    pik_data = {}

            finding_data = r.get("data")
            if not finding_data and r.get("data_json"):
                try:
                    finding_data = json.loads(r["data_json"])
                except Exception:
                    finding_data = {}

            formatted_results.append(
                {
                    "id": r["id"],
                    "schema_type": r["schema_type"],
                    "similarity": r.get("similarity", 0.0),
                    "distance": r.get("distance", 1.0),
                    "status": r.get("status", "confirmed"),
                    "pik": pik_data,
                    "data": finding_data,
                    "created_at": r.get("created_at"),
                    "updated_at": r.get("updated_at"),
                }
            )

        return json.dumps(
            {
                "session_id": sess_id,
                "query": query,
                "total_matched": len(formatted_results),
                "findings": formatted_results,
            },
            indent=2,
        )

    @server.tool()
    async def execute_tool(
        tool_name: str,
        target: str,
        arguments: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        timeout_seconds: Union[int, float] = 120,
        include_raw: bool = False,
    ) -> str:
        """Execute a security tool action under process supervision and policy gating.

        Args:
            tool_name: Registered security tool name (e.g. 'nmap', 'ffuf', 'whois').
            target: Target host, domain, IP, or URL.
            arguments: Tool parameters or flags (e.g. {"flags": ["-sV", "-p80"]}).
            session_id: Target investigation session ID.
            timeout_seconds: Seconds to await execution before detaching to background (default: 120).
            include_raw: Whether to include sanitized untrusted stdout inside <untrusted_scan_output> tags.
        """
        sess_id = await _resolve_session(session_id)
        registry = gw.registry
        if not registry.get_tool(tool_name):
            return json.dumps(
                {
                    "error": "ToolNotFound",
                    "message": f"Tool '{tool_name}' is not registered in Ether arsenal.",
                    "remediation": "Check registered tools via 'ether tool list'.",
                },
                indent=2,
            )

        args_dict = arguments or {}
        raw_flags = args_dict.get("flags", [])
        if isinstance(raw_flags, list):
            flags_str = " ".join(str(f) for f in raw_flags)
            flags_list = [str(f) for f in raw_flags]
        else:
            flags_str = str(raw_flags)
            flags_list = [flags_str] if flags_str else []

        # Preflight verification gate
        report = gw.preflight_verify(tool_name=tool_name, target=target, flags=flags_str)
        if not report.is_valid:
            error_list = [
                {
                    "title": e.title,
                    "description": e.description,
                    "remediation": e.remediation_hint,
                }
                for e in report.errors
            ]
            return json.dumps(
                {
                    "error": "PreflightGateRejected",
                    "message": f"Execution of '{tool_name}' against '{target}' rejected by policy {gw.policy.value}.",
                    "errors": error_list,
                    "remediation": error_list[0]["remediation"]
                    if error_list
                    else "Adjust target scope or policy.",
                },
                indent=2,
            )

        # Target finding inference and persistence
        target_finding = gw.infer_target_finding(target)
        target_node_id = await store.upsert_finding(sess_id, target_finding)

        action = ActionRequest(
            session_id=UUID(sess_id),
            tool_name=tool_name,
            target_entity_id=target_node_id,
            params={"target": target, "flags": flags_list},
        )

        try:
            action_id = await exec_sess.dispatch(action)
        except Exception as e:
            return json.dumps(
                {
                    "error": type(e).__name__,
                    "message": str(e),
                    "remediation": "Verify tool arguments and input schema requirements.",
                },
                indent=2,
            )

        async def _await_events() -> tuple[int, Optional[str]]:
            exit_code = 0
            err_msg = None
            async for event in exec_sess.subscribe(action_id):
                if isinstance(event, ExecutionCompleted):
                    exit_code = 0
                elif isinstance(event, ExecutionFailed):
                    exit_code = 1
                    err_msg = event.error
            return exit_code, err_msg

        try:
            exit_code, err_msg = await asyncio.wait_for(_await_events(), timeout=timeout_seconds)
            compiler = GraphTelemetryCompiler(store, sess_id, execution_session=exec_sess)
            diff = await compiler.compute_graph_diff(action_id=str(action_id))
            result: Dict[str, Any] = {
                "status": "completed" if exit_code == 0 else "failed",
                "action_id": str(action_id),
                "exit_code": exit_code,
                "error": err_msg,
                "diff": diff,
                "status_breakdown": diff.get("status_breakdown", {}),
                "summary": f"Execution of {tool_name} completed with {diff['total_delta_count']} new or updated findings.",
            }
            if include_raw:
                raw_text = "".join(exec_sess.get_output_history(action_id))
                result["untrusted_output"] = sanitize_untrusted_output(raw_text)
            return json.dumps(result, indent=2)
        except asyncio.TimeoutError:
            return json.dumps(
                {
                    "status": "running",
                    "action_id": str(action_id),
                    "message": f"Execution exceeded {timeout_seconds}s deadline and is continuing in background. Use get_diff(action_id='{action_id}') to inspect findings.",
                    "tokens_consumed": 0,
                },
                indent=2,
            )

    @server.tool()
    async def abort_action(action_id: str) -> str:
        """Abort or cancel an active execution by action ID.

        Args:
            action_id: Active action UUID string to cancel.
        """
        try:
            act_uuid = UUID(action_id)
        except Exception:
            return json.dumps(
                {"error": "InvalidActionId", "message": f"Invalid action UUID: '{action_id}'"}
            )

        success = await exec_sess.kill_job(act_uuid)
        return json.dumps({"action_id": action_id, "aborted": success}, indent=2)

    return server
