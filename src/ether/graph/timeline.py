"""Deep module managing session action timeline, execution audit trails, and event lifecycle."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import aiosqlite

from ether.schemas.power import ActionRequest

if TYPE_CHECKING:
    from ether.graph.store import GraphStore


class ActionTimelineRepository:
    """The deep module managing persistent event logging, audit trails,

    and active/closed tab status for investigation sessions.
    """

    def __init__(self, store: GraphStore):
        self.store = store

    async def append_event(
        self,
        session_id: str,
        action: ActionRequest,
        result: Dict[str, Any],
        message: str,
    ) -> None:
        """Append a structured action/result event to the session event log."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                """INSERT INTO event_log (session_id, action_payload, result_payload, human_readable, schema_type, finding_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    action.model_dump_json(),
                    json.dumps(result),
                    message,
                    "system.event",
                    "{}",
                ),
            )

        await self.store.run_write_operation(_op, session_id=session_id)

    async def log_audit_event(
        self, session_id: str, action_name: str, message: str, status: str
    ) -> None:
        """Append an audit lifecycle event (e.g. session closed/reopened) to event_log."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                """INSERT INTO event_log (session_id, action_payload, result_payload, human_readable, schema_type, finding_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    json.dumps({"action": action_name}),
                    json.dumps({"status": status}),
                    message,
                    f"system.{action_name}",
                    "{}",
                ),
            )

        await self.store.run_write_operation(_op, session_id=session_id, enforce_open=False)

    async def get_event_log(self, session_id: str) -> List[Dict[str, Any]]:
        """Fetch all non-closed events for a session in chronological order."""
        async with self.store.get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM event_log WHERE session_id = ? AND (closed IS NULL OR closed = 0) ORDER BY timestamp ASC, id ASC",
                (session_id,),
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def mark_event_closed(self, action_id: str, session_id: Optional[str] = None) -> None:
        """Mark an event log entry as closed/deleted from the active view."""

        async def _op(db: aiosqlite.Connection) -> None:
            if session_id:
                await db.execute(
                    "UPDATE event_log SET closed = 1 WHERE session_id = ? AND (json_extract(action_payload, '$.action_id') = ? OR action_payload LIKE ?)",
                    (session_id, action_id, f'%"{action_id}"%'),
                )
            else:
                await db.execute(
                    "UPDATE event_log SET closed = 1 WHERE json_extract(action_payload, '$.action_id') = ? OR action_payload LIKE ?",
                    (action_id, f'%"{action_id}"%'),
                )

        await self.store.run_write_operation(_op, session_id=session_id)

    async def get_closed_events_count(self, session_id: str) -> int:
        """Get the count of closed events/tabs for a session."""
        async with self.store.get_read_conn() as db:
            cursor = await db.execute(
                "SELECT COUNT(*) FROM event_log WHERE session_id = ? AND closed = 1",
                (session_id,),
            )
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def compact_timeline(self, session_id: str, keep_closed_events: int = 500) -> int:
        """Prune older closed event logs to prevent unbounded timeline table growth."""

        async def _op(db: aiosqlite.Connection) -> int:
            cursor = await db.execute(
                "SELECT id FROM event_log WHERE session_id = ? AND closed = 1 ORDER BY timestamp DESC, id DESC",
                (session_id,),
            )
            rows = list(await cursor.fetchall())
            if len(rows) > keep_closed_events:
                if keep_closed_events == 0:
                    cursor_del = await db.execute(
                        "DELETE FROM event_log WHERE session_id = ? AND closed = 1",
                        (session_id,),
                    )
                else:
                    cutoff_id = rows[keep_closed_events][0]
                    cursor_del = await db.execute(
                        "DELETE FROM event_log WHERE session_id = ? AND closed = 1 AND id <= ?",
                        (session_id, cutoff_id),
                    )
                return cursor_del.rowcount
            return 0

        return await self.store.run_write_operation(_op, session_id=session_id)

    async def query_timeline(
        self,
        session_id: str,
        schema_type: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query chronological timeline events with optional schema and keyword filters."""
        query = "SELECT * FROM event_log WHERE session_id = ? AND (closed IS NULL OR closed = 0)"
        params: List[Any] = [session_id]

        if schema_type:
            query += " AND schema_type = ?"
            params.append(schema_type)

        if keyword:
            query += (
                " AND (human_readable LIKE ? OR action_payload LIKE ? OR result_payload LIKE ?)"
            )
            like_kw = f"%{keyword}%"
            params.extend([like_kw, like_kw, like_kw])

        query += " ORDER BY timestamp ASC, id ASC LIMIT ?"
        params.append(limit)

        async with self.store.get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(query, tuple(params))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def replay_session_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Replay session timeline history into a normalized, structured event sequence."""
        raw_events = await self.get_event_log(session_id)
        replayed: List[Dict[str, Any]] = []

        for row in raw_events:
            try:
                action_data = json.loads(row.get("action_payload") or "{}")
            except Exception:
                action_data = {}
            try:
                result_data = json.loads(row.get("result_payload") or "{}")
            except Exception:
                result_data = {}

            replayed.append(
                {
                    "id": row.get("id"),
                    "timestamp": row.get("timestamp"),
                    "schema_type": row.get("schema_type"),
                    "message": row.get("human_readable"),
                    "tool_name": action_data.get("tool_name"),
                    "action_id": action_data.get("action_id"),
                    "status": result_data.get("status") or "completed",
                    "details": result_data,
                }
            )
        return replayed
