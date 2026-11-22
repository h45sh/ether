"""Native Model Context Protocol (MCP) server implementation for Ether."""

import json
import logging
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer

from ether.gateway.gate import ActionGateway, GatePolicy
from ether.graph.store import GraphStore
from ether.graph.telemetry import GraphTelemetryCompiler

logger = logging.getLogger(__name__)


def create_mcp_server(
    store: GraphStore,
    default_session_id: Optional[str] = None,
    policy: GatePolicy = GatePolicy.SAFE,
    gateway: Optional[ActionGateway] = None,
    execution_session: Optional[Any] = None,
) -> MCPServer:
    """Construct an MCP server instance exposing canonical security tools."""
    server = MCPServer("ether")

    async def _resolve_session(session_id: Optional[str]) -> str:
        """Resolve target session ID from argument, default, or active sandbox."""
        if session_id:
            return session_id
        if default_session_id:
            return default_session_id
        _, sess_id = await store.get_or_create_learning_sandbox()
        return sess_id

    @server.tool()
    async def query_graph(
        session_id: Optional[str] = None,
        schema_type: Optional[str] = None,
        limit: int = 100,
    ) -> str:
        """Query normalized cybersecurity findings and entities in the graph.

        Args:
            session_id: Target session ID (optional, defaults to active session).
            schema_type: Filter by schema type (e.g. 'network.host', 'network.service').
            limit: Maximum number of nodes to return (default: 100).
        """
        sess_id = await _resolve_session(session_id)
        if schema_type:
            raw_nodes = await store.query(schema_type, session_id=sess_id)
        else:
            raw_nodes = await store.get_all_nodes(sess_id)

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
            e
            for e in all_edges
            if e["source_id"] == entity_id or e["target_id"] == entity_id
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
        compiler = GraphTelemetryCompiler(store, sess_id, execution_session=execution_session)
        diff = await compiler.compute_graph_diff(
            baseline_timestamp=baseline_timestamp, action_id=action_id
        )
        return json.dumps(diff, indent=2)

    return server
