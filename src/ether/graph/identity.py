"""Deep module managing cryptographic identity anchoring and cross-IP entity migrations."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple

import aiosqlite


class IdentityAnchoringEngine:
    """Manages invariant cryptographic service identity anchors and tracks entity migrations."""

    @staticmethod
    def extract_anchor_hash(finding: Any) -> Optional[str]:
        """Extract or compute invariant cryptographic fingerprint from a finding."""
        anchor_hash = getattr(finding, "anchor_hash", None)
        if not anchor_hash and getattr(finding, "data", None):
            for key in (
                "anchor_hash",
                "tls_cert_sha256",
                "ssh_hostkey_fingerprint",
                "favicon_hash",
                "soa_serial",
            ):
                val = finding.data.get(key)
                if val:
                    prefix = (
                        "tls"
                        if "tls" in key
                        else (
                            "ssh"
                            if "ssh" in key
                            else (
                                "favicon" if "favicon" in key else ("soa" if "soa" in key else "")
                            )
                        )
                    )
                    anchor_hash = f"{prefix}:{val}" if prefix else str(val)
                    break
        return anchor_hash

    @staticmethod
    async def resolve_migrations(
        db: aiosqlite.Connection,
        session_id: str,
        node_metadata: Dict[str, Dict[str, Any]],
        action_id: Optional[str] = None,
    ) -> Tuple[Set[Tuple[str, str, str, str]], Set[str], List[Tuple[Any, ...]]]:
        """Detect cross-IP migrations for entities sharing invariant cryptographic anchors.

        Returns:
            Tuple of:
            - migration_edges: Set of (session_id, old_id, new_id, 'anchored_identity')
            - stale_migrated_node_ids: Set of historical node IDs to mark as stale
            - migration_event_params: Event log records for identity migration auditing
        """
        migration_edges: Set[Tuple[str, str, str, str]] = set()
        stale_migrated_node_ids: Set[str] = set()
        migration_event_params: List[Tuple[Any, ...]] = []

        for nid, meta in node_metadata.items():
            anchor = meta.get("anchor_hash")
            if not anchor:
                continue

            cursor = await db.execute(
                """
                SELECT n.id, n.status,
                       (SELECT 1 FROM edges e
                        WHERE e.session_id = n.session_id
                          AND e.source_id = n.id
                          AND e.target_id = ?
                          AND e.relation_type = 'anchored_identity') as has_edge
                FROM nodes n
                WHERE n.session_id = ? AND n.anchor_hash = ? AND n.id != ?
                ORDER BY n.updated_at DESC
                """,
                (nid, session_id, anchor, nid),
            )
            matching_nodes = await cursor.fetchall()
            for old_id, old_status, has_edge in matching_nodes:
                migration_edges.add((session_id, old_id, nid, "anchored_identity"))
                if old_status != "stale":
                    stale_migrated_node_ids.add(old_id)
                if not has_edge:
                    migration_event_params.append(
                        (
                            session_id,
                            "identity.migration",
                            json.dumps(
                                {
                                    "anchor_hash": anchor,
                                    "from_node_id": old_id,
                                    "to_node_id": nid,
                                }
                            ),
                            f"Anchored identity migration: {old_id} -> {nid} ({anchor})",
                            json.dumps({"action_id": action_id} if action_id else {}),
                            "{}",
                        )
                    )

        return migration_edges, stale_migrated_node_ids, migration_event_params

    @staticmethod
    async def get_anchored_migrations(
        db: aiosqlite.Connection,
        session_id: str,
        action_id: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Fetch recorded anchored identity migrations for a session."""
        db.row_factory = aiosqlite.Row
        query = """
            SELECT finding_json, timestamp, action_payload
            FROM event_log
            WHERE session_id = ? AND schema_type = 'identity.migration'
            ORDER BY timestamp ASC
        """
        cursor = await db.execute(query, (session_id,))
        rows = await cursor.fetchall()
        migrations = []
        for r in rows:
            try:
                payload = json.loads(r["finding_json"])
                act_meta = json.loads(r["action_payload"]) if r["action_payload"] else {}
                if action_id and act_meta.get("action_id") != action_id:
                    continue
                migrations.append(
                    {
                        "anchor_hash": payload.get("anchor_hash", ""),
                        "from_node_id": payload.get("from_node_id", ""),
                        "to_node_id": payload.get("to_node_id", ""),
                        "timestamp": r["timestamp"],
                    }
                )
            except Exception:
                continue
        return migrations
