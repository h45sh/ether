"""High-level asynchronous Python SDK facade for Ether."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence, Union

from ether import paths
from ether.config import EtherSettings
from ether.gateway.gate import ActionGateway, GatePolicy
from ether.graph.analytics import GraphAnalyticsEngine
from ether.graph.store import GraphStore
from ether.graph.telemetry import GraphTelemetryCompiler
from ether.registry.registry import ToolRegistry
from ether.services.execution import SupervisedExecutionService


class Ether:
    """Ergonomic, high-velocity Python SDK facade over Ether's engine, gateway, and graph."""

    def __init__(
        self,
        store: GraphStore,
        registry: ToolRegistry,
        gateway: ActionGateway,
        settings: EtherSettings,
        session_id: Optional[str] = None,
    ) -> None:
        self.store = store
        self.registry = registry
        self.gateway = gateway
        self.settings = settings
        self.session_id = session_id
        self.exec_session = gateway.create_session()
        self._service = SupervisedExecutionService(
            gateway=gateway,
            store=store,
            execution_session=self.exec_session,
        )

    @classmethod
    @asynccontextmanager
    async def open(
        cls,
        db_path: Optional[str] = None,
        policy: Optional[Union[str, GatePolicy]] = None,
        data_dir: Optional[str] = None,
        tools_dir: Optional[str] = None,
        session_id: Optional[str] = None,
        settings: Optional[EtherSettings] = None,
    ) -> AsyncIterator["Ether"]:
        """Open an initialized Ether SDK session with automatic resource cleanup."""
        cfg = settings or EtherSettings.load(data_dir=data_dir)
        resolved_data_dir = data_dir or cfg.paths.data_dir or paths.get_default_data_dir()
        resolved_db = db_path or cfg.paths.db_path or paths.get_default_db_path(resolved_data_dir)
        resolved_tools = tools_dir or cfg.paths.tools_dir

        if isinstance(policy, GatePolicy):
            gate_policy = policy
        elif isinstance(policy, str):
            gate_policy = (
                GatePolicy.UNRESTRICTED if policy.lower() == "unrestricted" else GatePolicy.SAFE
            )
        else:
            gate_policy = (
                GatePolicy.UNRESTRICTED if cfg.gateway.policy == "unrestricted" else GatePolicy.SAFE
            )

        reg = ToolRegistry(tools_dir=resolved_tools, settings=cfg)
        reg.load_tools()

        store = GraphStore(resolved_db, settings=cfg)
        await store.initialize()
        try:
            if session_id is None:
                _, session_id = await store.get_or_create_default_session()
            gw = ActionGateway(registry=reg, store=store, policy=gate_policy, settings=cfg)
            yield cls(
                store=store,
                registry=reg,
                gateway=gw,
                settings=cfg,
                session_id=session_id,
            )
        finally:
            await store.close()

    def search_tools(
        self,
        query: Optional[str] = None,
        accepts: Optional[str] = None,
        produces: Optional[str] = None,
        include_profiles: bool = True,
    ) -> List[Dict[str, Any]]:
        """Search registered tools by keyword or input/output schema."""
        return self.registry.search_tools(
            query=query,
            accepts=accepts,
            produces=produces,
            include_profiles=include_profiles,
        )

    async def run(
        self,
        tool_name: str,
        target: str,
        profile: Optional[str] = None,
        flags: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[float] = None,
        include_raw: bool = False,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a tool under supervision with optional profile and explicit flags."""
        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else self.settings.execution.default_timeout_sec
        )
        arguments = {"flags": list(flags)} if flags else None
        return await self._service.execute_tool(
            tool_name=tool_name,
            target=target,
            arguments=arguments,
            session_id=session_id or self.session_id,
            timeout_seconds=timeout,
            include_raw=include_raw,
            profile=profile,
        )

    async def pipeline(
        self,
        expression: str,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a multi-stage chained pipeline expression."""
        return await self._service.execute_pipeline(
            expression=expression,
            session_id=session_id or self.session_id,
        )

    async def query(
        self,
        schema_type: Optional[str] = None,
        limit: Optional[int] = None,
        include_stale: bool = False,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query normalized findings from the session graph."""
        sid = session_id or self.session_id or ""
        max_rows = limit if limit is not None else self.settings.telemetry.default_query_limit
        if schema_type:
            rows = await self.store.query(schema_type, session_id=sid, include_stale=include_stale)
        else:
            rows = await self.store.get_all_nodes(sid, include_stale=include_stale)
        return rows[:max_rows]

    async def diff(
        self,
        action_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compute zero-token set-theoretic graph delta."""
        sid = session_id or self.session_id or ""
        compiler = GraphTelemetryCompiler(self.store, sid, execution_session=self.exec_session)
        return await compiler.compute_graph_diff(action_id=action_id)

    async def snapshot(
        self,
        token_budget: Optional[int] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compile a token-budgeted telemetry snapshot of the session graph."""
        sid = session_id or self.session_id or ""
        budget = (
            token_budget
            if token_budget is not None
            else self.settings.telemetry.default_token_budget
        )
        compiler = GraphTelemetryCompiler(self.store, sid, execution_session=self.exec_session)
        return await compiler.compile_telemetry_snapshot(max_tokens=budget)

    async def blast_radius(
        self,
        entity_id: str,
        max_depth: int = 10,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compute reachable blast radius from a starting entity ID."""
        sid = session_id or self.session_id or ""
        nodes = await self.store.get_all_nodes(sid)
        edges = await self.store.get_all_edges(sid)
        engine = GraphAnalyticsEngine(nodes, edges)
        reachable = engine.calculate_blast_radius(entity_id, max_depth=max_depth)
        return {
            "session_id": sid,
            "entity_id": entity_id,
            "reachable_ids": sorted(reachable),
            "count": len(reachable),
        }
