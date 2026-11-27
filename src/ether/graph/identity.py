"""Deep module managing cryptographic identity anchoring and cross-IP entity migrations."""

from __future__ import annotations

import json
import urllib.parse
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
    def _extract_origin(
        pik: Dict[str, Any], data: Dict[str, Any]
    ) -> Optional[Tuple[str, Optional[int]]]:
        """Extract canonical (host_or_netloc, port) service origin for migration disambiguation."""
        host_ip = pik.get("host_ip") or data.get("host_ip")
        port = pik.get("port") if pik.get("port") is not None else data.get("port")
        url = pik.get("url") or data.get("url")
        if url and (not host_ip or port is None):
            parsed = urllib.parse.urlparse(str(url))
            if not host_ip and parsed.hostname:
                host_ip = parsed.hostname
            if port is None and parsed.port is not None:
                port = parsed.port
            elif port is None and parsed.scheme in ("http", "https"):
                port = 443 if parsed.scheme == "https" else 80
        if not host_ip:
            return None
        return (str(host_ip), int(port) if port is not None else None)

    @staticmethod
    async def resolve_migrations(
        db: aiosqlite.Connection,
        session_id: str,
        node_metadata: Dict[str, Dict[str, Any]],
        action_id: Optional[str] = None,
    ) -> Tuple[Set[Tuple[str, str, str, str]], Set[str], List[Tuple[Any, ...]]]:
        """Detect cross-origin migrations for entities sharing invariant cryptographic anchors.

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
            new_origin = IdentityAnchoringEngine._extract_origin(
                meta.get("pik") or {}, meta.get("data") or {}
            )

            cursor = await db.execute(
                """
                SELECT n.id, n.status, n.pik_json, n.data_json,
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
            for old_id, old_status, old_pik_raw, old_data_raw, has_edge in matching_nodes:
                if new_origin is not None:
                    try:
                        old_pik = json.loads(old_pik_raw) if old_pik_raw else {}
                        old_data = json.loads(old_data_raw) if old_data_raw else {}
                    except Exception:
                        old_pik, old_data = {}, {}
                    old_origin = IdentityAnchoringEngine._extract_origin(old_pik, old_data)
                    if old_origin is not None and old_origin == new_origin:
                        # Distinct URL paths on the same (host_ip, port) are not migrations
                        continue

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
