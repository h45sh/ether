"""Agent Telemetry & Context Compiler for Ether.

Compiles deterministic, token-budgeted graph snapshots and zero-token semantic diffs
for autonomous agents, fulfilling Epoch 2 (Agent Telemetry Protocol).
"""

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

from ether.common.algorithms import knapsack_01
from ether.graph.analytics import GraphAnalyticsEngine
from ether.graph.store import GraphStore
from ether.schemas.base import BaseFinding


def _parse_timestamp(val: Any) -> float:
    """Parse float, integer, ISO string, or SQLite timestamp into float epoch seconds."""
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, datetime):
        return val.timestamp()
    if isinstance(val, str):
        val = val.strip()
        try:
            return datetime.fromisoformat(val).timestamp()
        except Exception:
            pass
        try:
            return (
                datetime.strptime(val, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            )
        except Exception:
            pass
    return 0.0


class GraphTelemetryCompiler:
    """Compiles point-in-time graph state snapshots and semantic diffs for AI agents.

    Uses dynamic programming 0/1 knapsack to fit the highest-utility findings into a strict
    token window and produces zero-token graph diffs for incremental agent reasoning loops.
    """

    def __init__(
        self,
        store: GraphStore,
        session_id: str,
        execution_session: Optional[Any] = None,
    ) -> None:
        self.store = store
        self.session_id = session_id
        self.execution_session = execution_session

    @staticmethod
    def budget_findings(
        findings: List[BaseFinding],
        max_tokens: int = 4000,
        chars_per_token: float = 4.0,
    ) -> List[BaseFinding]:
        """Select optimal subset of findings using 0/1 knapsack dynamic programming.

        Maximizes information utility under the target token window while prioritizing
        exploitable vulnerabilities, discovered credentials, and critical network assets.
        """

        def _estimate_weight(f: BaseFinding) -> int:
            raw_len = len(f.model_dump_json())
            return max(1, int(raw_len / chars_per_token))

        def _estimate_utility(f: BaseFinding) -> float:
            score = 10.0
            st = str(f.schema_type).lower()
            if "vulnerability" in st or "exploit" in st:
                score += 50.0
            elif "credential" in st:
                score += 80.0
            elif "service" in st:
                score += 20.0
            elif "host" in st:
                score += 15.0

            if getattr(f, "data", None) and isinstance(f.data, dict):
                sev = str(f.data.get("severity", "")).lower()
                if "crit" in sev:
                    score += 60.0
                elif "high" in sev:
                    score += 40.0
                elif "med" in sev:
                    score += 20.0
                elif "low" in sev:
                    score += 10.0
            return score

        return knapsack_01(findings, max_tokens, _estimate_weight, _estimate_utility)

    @staticmethod
    def resolve_entity_variables(pik: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Extract investigation variables from primary identity key dictionary."""
        resolved: Dict[str, Any] = {}
        if pik:
            target = pik.get("ip") or pik.get("domain") or pik.get("host_ip")
            if target:
                resolved["TARGET"] = target
            if "port" in pik:
                resolved["PORT"] = pik["port"]
            if "service" in pik or "service_name" in pik:
                resolved["SERVICE"] = pik.get("service") or pik.get("service_name")
            if "protocol" in pik:
                resolved["PROTOCOL"] = pik["protocol"]
        return resolved

    async def compile_telemetry_snapshot(
        self,
        selected_entity_id: Optional[str] = None,
        max_tokens: int = 4000,
        variable_resolver: Optional[Callable[[Optional[Dict[str, Any]]], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Compile a point-in-time state snapshot of the active investigation session."""
        session_data = await self.store.get_session(self.session_id)
        if not session_data:
            raise ValueError(f"Session '{self.session_id}' not found.")

        # 1. Resolve selected entity
        selected_entity: Optional[BaseFinding] = None
        resolved_vars: Dict[str, Any] = {}
        resolver = variable_resolver or self.resolve_entity_variables

        if selected_entity_id:
            node_data = await self.store.get_node(self.session_id, selected_entity_id)
            if node_data:
                pik = json.loads(node_data["pik_json"])
                selected_entity = BaseFinding(
                    schema_type=node_data["schema_type"],
                    pik=pik,
                    data=json.loads(node_data["data_json"]),
                    status=node_data.get("status", "confirmed"),
                )
                resolved_vars = resolver(pik)

        # 2. Ingest all session findings and apply knapsack budgeting
        raw_nodes = await self.store.get_all_nodes(self.session_id)
        raw_edges = await self.store.get_all_edges(self.session_id)
        findings: List[BaseFinding] = []
        for n in raw_nodes:
            try:
                findings.append(
                    BaseFinding(
                        schema_type=n["schema_type"],
                        pik=json.loads(n["pik_json"]),
                        data=json.loads(n["data_json"]),
                        status=n.get("status", "confirmed"),
                    )
                )
            except Exception:
                continue

        budgeted = self.budget_findings(findings, max_tokens=max_tokens)
        stats = await self.store.get_stats(self.session_id)

        # 3. Graph analytics summary
        critical_count = 0
        if raw_nodes:
            analytics = GraphAnalyticsEngine(raw_nodes, raw_edges)
            critical_count = len(analytics.identify_critical_assets())

        # 4. Resolve active jobs from supervisor if attached
        active_jobs = []
        if self.execution_session and hasattr(self.execution_session, "get_active_jobs"):
            for job in self.execution_session.get_active_jobs():
                if str(getattr(job, "session_id", "")) == self.session_id:
                    active_jobs.append(job.to_dict() if hasattr(job, "to_dict") else vars(job))

        return {
            "session_id": self.session_id,
            "session_name": session_data.get("name", "Default"),
            "selected_entity": (
                selected_entity.model_dump(mode="json") if selected_entity else None
            ),
            "resolved_vars": resolved_vars,
            "entity_counts": stats,
            "budgeted_findings": [f.model_dump(mode="json") for f in budgeted],
            "active_jobs": active_jobs,
            "graph_summary": {
                "total_nodes": len(raw_nodes),
                "total_edges": len(raw_edges),
                "critical_assets": critical_count,
            },
        }

    async def compute_graph_diff(
        self, baseline_timestamp: Union[float, str, datetime]
    ) -> Dict[str, Any]:
        """Compute the set-theoretic graph delta since baseline_timestamp: Δ = S_(t+1) \\ S_t."""
        nodes = await self.store.get_all_nodes(self.session_id)
        edges = await self.store.get_all_edges(self.session_id)
        baseline_ts = _parse_timestamp(baseline_timestamp)

        added_nodes = []
        updated_nodes = []
        for n in nodes:
            created_at = _parse_timestamp(n.get("created_at"))
            updated_at = _parse_timestamp(n.get("updated_at"))
            if created_at > baseline_ts:
                added_nodes.append(
                    {
                        "id": n["id"],
                        "schema_type": n["schema_type"],
                        "pik": json.loads(n["pik_json"]),
                        "data": json.loads(n["data_json"]),
                    }
                )
            elif updated_at > baseline_ts:
                updated_nodes.append(
                    {
                        "id": n["id"],
                        "schema_type": n["schema_type"],
                        "pik": json.loads(n["pik_json"]),
                        "data": json.loads(n["data_json"]),
                    }
                )

        added_edges = []
        for e in edges:
            edge_ts = _parse_timestamp(e.get("created_at") or e.get("updated_at"))
            if edge_ts > baseline_ts:
                added_edges.append(
                    {
                        "session_id": e.get("session_id", self.session_id),
                        "source_id": e["source_id"],
                        "target_id": e["target_id"],
                        "relation_type": e.get("relation_type", "relates_to"),
                    }
                )

        return {
            "baseline_timestamp": baseline_timestamp,
            "added_nodes": added_nodes,
            "updated_nodes": updated_nodes,
            "added_edges": added_edges,
            "tokens_consumed": 0,
        }
