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
        objective: Optional[str] = None,
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

        # 2.5 Offline Vector RAG Retrieval for Objective
        rag_findings = []
        if objective and hasattr(self.store, "semantic_search"):
            try:
                rag_findings = await self.store.semantic_search(
                    session_id=self.session_id,
                    query=objective,
                    limit=5,
                )
            except Exception:
                rag_findings = []

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
            "rag_findings": rag_findings,
            "active_jobs": active_jobs,
            "graph_summary": {
                "total_nodes": len(raw_nodes),
                "total_edges": len(raw_edges),
                "critical_assets": critical_count,
            },
        }

    async def compute_graph_diff(
        self,
        baseline_timestamp: Optional[Union[float, str, datetime]] = None,
        action_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compute the set-theoretic graph delta: Δ = S_(t+1) \\ S_t.

        Can be queried by exact `action_id` (action-scoped diff) or `baseline_timestamp`.
        """
        # 1. Reconcile state decay deterministically before computing delta
        decay_info = await self.store.reconcile_state_decay(self.session_id)
        status_counts = decay_info.get("status_breakdown") or decay_info.get("status_counts", {})
        status_breakdown = {
            "confirmed": status_counts.get("confirmed", 0),
            "flapping": status_counts.get("flapping", 0),
            "stale": status_counts.get("stale", 0),
        }
        transitions = decay_info.get("transitions", [])
        transition_map = {t["id"]: t for t in transitions}

        nodes = await self.store.get_all_nodes(self.session_id, include_stale=True)
        edges = await self.store.get_all_edges(self.session_id)
        node_map = {n["id"]: n for n in nodes}

        added_nodes = []
        updated_nodes = []
        added_edges = []

        if action_id:
            for n in nodes:
                if n.get("action_id") == action_id:
                    node_item = {
                        "id": n["id"],
                        "schema_type": n["schema_type"],
                        "pik": json.loads(n["pik_json"]),
                        "data": json.loads(n["data_json"]),
                        "status": n.get("status", "confirmed"),
                    }
                    if n["id"] in transition_map:
                        t = transition_map[n["id"]]
                        node_item["new_attributes"] = {"status": t["to"]}
                        node_item["previous_attributes"] = {"status": t["from"]}
                    if n.get("created_action_id") == action_id:
                        added_nodes.append(node_item)
                    else:
                        updated_nodes.append(node_item)

            for e in edges:
                if e.get("action_id") == action_id:
                    added_edges.append(
                        {
                            "session_id": e.get("session_id", self.session_id),
                            "source_id": e["source_id"],
                            "target_id": e["target_id"],
                            "relation_type": e.get("relation_type", "relates_to"),
                        }
                    )
        elif baseline_timestamp is not None:
            baseline_ts = _parse_timestamp(baseline_timestamp)
            for n in nodes:
                created_at = _parse_timestamp(n.get("created_at"))
                updated_at = _parse_timestamp(n.get("updated_at"))
                node_item = {
                    "id": n["id"],
                    "schema_type": n["schema_type"],
                    "pik": json.loads(n["pik_json"]),
                    "data": json.loads(n["data_json"]),
                    "status": n.get("status", "confirmed"),
                }
                if n["id"] in transition_map:
                    t = transition_map[n["id"]]
                    node_item["new_attributes"] = {"status": t["to"]}
                    node_item["previous_attributes"] = {"status": t["from"]}
                if created_at > baseline_ts:
                    added_nodes.append(node_item)
                elif updated_at > baseline_ts:
                    updated_nodes.append(node_item)

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

        # Include nodes that underwent state transitions during this diff run
        seen_ids = {n["id"] for n in added_nodes} | {n["id"] for n in updated_nodes}
        for t in transitions:
            nid = t["id"]
            if nid not in seen_ids and nid in node_map:
                n = node_map[nid]
                updated_nodes.append(
                    {
                        "id": nid,
                        "schema_type": n["schema_type"],
                        "pik": json.loads(n["pik_json"]),
                        "data": json.loads(n["data_json"]),
                        "status": t["to"],
                        "new_attributes": {"status": t["to"]},
                        "previous_attributes": {"status": t["from"]},
                    }
                )
                seen_ids.add(nid)

        anchored_migrations = await self.store.get_anchored_migrations(
            self.session_id, action_id=action_id
        )

        total_delta_count = (
            len(added_nodes)
            + len(updated_nodes)
            + len(added_edges)
            + len(anchored_migrations)
        )
        return {
            "session_id": self.session_id,
            "action_id": action_id,
            "baseline_timestamp": baseline_timestamp,
            "added_nodes": added_nodes,
            "updated_nodes": updated_nodes,
            "added_edges": added_edges,
            "status_breakdown": status_breakdown,
            "anchored_migrations": anchored_migrations,
            "total_delta_count": total_delta_count,
            "tokens_consumed": 0,
        }
