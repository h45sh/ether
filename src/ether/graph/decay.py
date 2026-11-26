"""Deep module managing temporal confidence decay and stale node lifecycle."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite


class TemporalDecayEngine:
    """Deterministically evaluates and reconciles temporal state decay for session graphs."""

    @staticmethod
    async def reconcile_state_decay(
        db: aiosqlite.Connection,
        session_id: str,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Deterministically evaluate and reconcile temporal state decay for a session.

        Transitions:
        - confirmed -> stale (if elapsed > ttl and not flapping)
        - confirmed -> flapping (if elapsed > ttl and oscillations >= 2)
        - flapping -> stale (if elapsed > 2 * ttl)
        - proposed -> stale (if elapsed > ttl)
        - stale -> confirmed (if re-observed within ttl)
        """
        if now is None:
            now = datetime.now(UTC)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=UTC)

        transitions: List[Dict[str, str]] = []
        status_updates: List[Tuple[str, str, str, str]] = []
        metadata_updates: List[Tuple[str, str, str]] = []

        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT id, status, observation_count, ttl_seconds, last_seen_at, data_json FROM nodes WHERE session_id = ?",
            (session_id,),
        )
        rows = await cursor.fetchall()

        status_counts = {"confirmed": 0, "flapping": 0, "stale": 0, "proposed": 0}

        for row in rows:
            nid = row["id"]
            current_status = row["status"] or "confirmed"
            ttl = int(row["ttl_seconds"] or 3600)
            last_seen_val = row["last_seen_at"]

            last_seen_dt = now
            if last_seen_val:
                if isinstance(last_seen_val, str):
                    dt_str = last_seen_val.replace("Z", "+00:00")
                    if "T" not in dt_str and " " in dt_str:
                        dt_str = dt_str.replace(" ", "T")
                    try:
                        parsed_dt = datetime.fromisoformat(dt_str)
                        last_seen_dt = (
                            parsed_dt.replace(tzinfo=UTC) if parsed_dt.tzinfo is None else parsed_dt
                        )
                    except Exception:
                        last_seen_dt = now
                elif isinstance(last_seen_val, datetime):
                    last_seen_dt = (
                        last_seen_val.replace(tzinfo=UTC)
                        if last_seen_val.tzinfo is None
                        else last_seen_val
                    )

            elapsed = (now - last_seen_dt).total_seconds()

            data = {}
            if row["data_json"]:
                try:
                    data = json.loads(row["data_json"])
                except Exception:
                    pass

            oscillations = int(data.get("oscillations", 0)) if isinstance(data, dict) else 0
            is_flapping_indicator = (
                bool(data.get("flapping", False)) if isinstance(data, dict) else False
            )
            has_flapped = oscillations >= 2 or is_flapping_indicator

            # Adaptive Volatility Scoring V_n in [0.0, 1.0] (ADR 0014)
            is_ephemeral = bool(data.get("ephemeral", False)) or bool(data.get("container", False))
            if oscillations == 0 and not is_ephemeral:
                volatility = 0.0
                effective_ttl = ttl
            else:
                raw_volatility = 0.1 + (0.2 * oscillations) + (0.3 if is_ephemeral else 0.0)
                volatility = round(min(1.0, max(0.1, raw_volatility)), 2)
                floor_ttl = min(ttl, 300)
                effective_ttl = max(floor_ttl, int(ttl * (1.0 - 0.75 * volatility)))

            data_updated = False
            if isinstance(data, dict) and data.get("volatility") != volatility:
                data["volatility"] = volatility
                data_updated = True

            new_status = current_status

            if elapsed > effective_ttl:
                if current_status == "confirmed":
                    new_status = "flapping" if (has_flapped or volatility >= 0.7) else "stale"
                elif current_status == "flapping":
                    if elapsed > 2 * effective_ttl:
                        new_status = "stale"
                elif current_status == "proposed":
                    new_status = "stale"

            if new_status != current_status:
                transitions.append({"id": nid, "from": current_status, "to": new_status})
                status_counts[new_status] = status_counts.get(new_status, 0) + 1
            else:
                status_counts[current_status] = status_counts.get(current_status, 0) + 1

            if new_status != current_status:
                data_json_str = json.dumps(data) if isinstance(data, dict) else row["data_json"]
                status_updates.append((new_status, data_json_str, session_id, nid))
            elif data_updated:
                data_json_str = json.dumps(data) if isinstance(data, dict) else row["data_json"]
                metadata_updates.append((data_json_str, session_id, nid))

        if status_updates:
            await db.executemany(
                "UPDATE nodes SET status = ?, data_json = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ? AND id = ?",
                status_updates,
            )
        if metadata_updates:
            await db.executemany(
                "UPDATE nodes SET data_json = ? WHERE session_id = ? AND id = ?",
                metadata_updates,
            )

        return {
            "transitions": transitions,
            "status_breakdown": status_counts,
            "reconciled_count": len(transitions),
        }

    @staticmethod
    async def prune_stale_nodes(
        db: aiosqlite.Connection,
        session_id: str,
        vector_index: Any,
        max_age_seconds: int = 604800,
        now: Optional[datetime] = None,
    ) -> int:
        """Permanently delete stale nodes and cascading vectors older than max_age_seconds."""
        if now is None:
            now = datetime.now(UTC)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=UTC)

        cutoff = (now - timedelta(seconds=max_age_seconds)).strftime("%Y-%m-%d %H:%M:%S")
        if vector_index:
            await vector_index.purge_stale_vectors(db, session_id, cutoff)

        cursor = await db.execute(
            """DELETE FROM nodes
               WHERE session_id = ?
                 AND status = 'stale'
                 AND datetime(last_seen_at) < datetime(?)""",
            (session_id, cutoff),
        )
        return cursor.rowcount
