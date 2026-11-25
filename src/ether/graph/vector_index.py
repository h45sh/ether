"""Vector embedding storage, sqlite-vec indexing, and semantic search for Ether."""

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

import aiosqlite

try:
    import sqlite_vec
except ImportError:
    sqlite_vec = None

from ether.common.embeddings import get_embedding_engine
from ether.schemas.base import BaseFinding

logger = logging.getLogger("ether.graph.vector_index")


class VectorIndex:
    """Encapsulates vector embeddings, sqlite-vec virtual table management, and semantic retrieval."""

    def __init__(self) -> None:
        self.sqlite_vec_available: bool = sqlite_vec is not None

    async def load_extension(self, conn: aiosqlite.Connection) -> None:
        """Attempt to load sqlite-vec extension into the connection if available."""
        if sqlite_vec is not None:
            try:
                await conn.enable_load_extension(True)
                await conn.load_extension(sqlite_vec.loadable_path())
                await conn.enable_load_extension(False)
            except Exception as e:
                logger.warning(f"Could not load sqlite-vec extension: {e}")

    async def sync_node_embeddings(
        self,
        db: aiosqlite.Connection,
        node_texts: List[Tuple[str, str]],
        session_id: str = "",
    ) -> None:
        """Embed and sync text representations for a list of (node_id, semantic_text) tuples."""
        if sqlite_vec is None or not node_texts:
            return

        engine = get_embedding_engine()
        vector_delete_params: List[Tuple[str, str]] = []
        vector_params: List[Tuple[str, str, bytes]] = []
        seen: set[str] = set()

        for nid, text in node_texts:
            if nid in seen:
                continue
            seen.add(nid)
            try:
                vec = engine.embed_text(text)
                serialized = sqlite_vec.serialize_float32(vec)
                vector_delete_params.append((session_id, nid))
                vector_params.append((session_id, nid, serialized))
            except Exception as e:
                logger.warning(f"Could not compute semantic embedding for node {nid}: {e}")

        if vector_params:
            try:
                await db.executemany(
                    "DELETE FROM vec_findings WHERE session_id = ? AND node_id = ?",
                    vector_delete_params,
                )
                await db.executemany(
                    "INSERT INTO vec_findings(session_id, node_id, embedding) VALUES (?, ?, ?)",
                    vector_params,
                )
            except Exception as e:
                logger.warning(f"Error syncing vectors to vec_findings: {e}")

    async def sync_findings_batch(
        self,
        db: aiosqlite.Connection,
        findings: List[BaseFinding],
        generate_node_id_func: Callable[[str, Dict[str, Any]], str],
        session_id: str = "",
    ) -> int:
        """Compute and store offline vector embeddings for a batch of findings in vec_findings."""
        if not findings or sqlite_vec is None:
            return 0

        engine = get_embedding_engine()
        vector_delete_params: List[Tuple[str, str]] = []
        vector_params: List[Tuple[str, str, bytes]] = []
        seen = set()

        for finding in findings:
            nid = generate_node_id_func(finding.schema_type, finding.pik)
            if nid in seen:
                continue
            seen.add(nid)
            try:
                semantic_text = finding.to_semantic_text()
                vec = engine.embed_text(semantic_text)
                serialized = sqlite_vec.serialize_float32(vec)
                vector_delete_params.append((session_id, nid))
                vector_params.append((session_id, nid, serialized))
            except Exception as e:
                logger.warning(f"Could not compute semantic embedding for finding {nid}: {e}")

        if not vector_params:
            return 0

        await db.executemany(
            "DELETE FROM vec_findings WHERE session_id = ? AND node_id = ?",
            vector_delete_params,
        )
        await db.executemany(
            "INSERT INTO vec_findings(session_id, node_id, embedding) VALUES (?, ?, ?)",
            vector_params,
        )
        return len(vector_params)

    async def semantic_search(
        self,
        db: aiosqlite.Connection,
        session_id: str,
        query: str,
        limit: int = 10,
        min_score: float = 0.0,
        schema_type: Optional[str] = None,
        include_stale: bool = False,
    ) -> List[Dict[str, Any]]:
        """Semantic search against session findings using offline vector embeddings."""
        if not query or not query.strip() or sqlite_vec is None:
            return []

        engine = get_embedding_engine()
        query_vec = engine.embed_text(query)
        serialized_query = sqlite_vec.serialize_float32(query_vec)
        k_candidates = max(limit * 5, 50) if (schema_type or not include_stale) else limit

        db.row_factory = aiosqlite.Row

        sql = """
            SELECT n.*, sub.distance
            FROM (
                SELECT node_id, distance
                FROM vec_findings
                WHERE embedding MATCH ? AND session_id = ? AND k = ?
            ) sub
            JOIN nodes n ON sub.node_id = n.id
            WHERE n.session_id = ?
        """
        params: List[Any] = [serialized_query, session_id, k_candidates, session_id]

        if not include_stale:
            sql += " AND n.status != 'stale'"

        if schema_type:
            sql += " AND n.schema_type = ?"
            params.append(schema_type)

        sql += " ORDER BY sub.distance ASC LIMIT ?"
        params.append(limit)

        cursor = await db.execute(sql, params)
        rows = await cursor.fetchall()

        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            distance = item.get("distance", 1.0)
            similarity = max(0.0, min(1.0, 1.0 - distance))
            if similarity < min_score:
                continue
            item["similarity"] = round(similarity, 4)
            if isinstance(item.get("pik_json"), str):
                try:
                    item["pik"] = json.loads(item["pik_json"])
                except Exception:
                    pass
            if isinstance(item.get("data_json"), str):
                try:
                    item["data"] = json.loads(item["data_json"])
                except Exception:
                    pass
            results.append(item)

        return results

    async def delete_workspace_vectors(self, db: aiosqlite.Connection, workspace_id: str) -> None:
        """Delete vectors associated with a workspace."""
        if sqlite_vec is not None:
            try:
                await db.execute(
                    """DELETE FROM vec_findings WHERE session_id IN (
                           SELECT id FROM sessions WHERE workspace_id = ?
                       )""",
                    (workspace_id,),
                )
            except Exception as e:
                logger.warning(f"Error deleting workspace vectors: {e}")

    async def delete_session_vectors(self, db: aiosqlite.Connection, session_id: str) -> None:
        """Delete vectors associated with a session."""
        if sqlite_vec is not None:
            try:
                await db.execute(
                    "DELETE FROM vec_findings WHERE session_id = ?",
                    (session_id,),
                )
            except Exception as e:
                logger.warning(f"Error deleting session vectors: {e}")

    async def purge_stale_vectors(
        self, db: aiosqlite.Connection, session_id: str, cutoff: str
    ) -> None:
        """Delete vectors for stale nodes older than cutoff."""
        if sqlite_vec is not None:
            try:
                await db.execute(
                    """DELETE FROM vec_findings
                       WHERE session_id = ?
                         AND node_id IN (
                             SELECT id FROM nodes
                             WHERE session_id = ?
                               AND status = 'stale'
                               AND datetime(last_seen_at) < datetime(?)
                         )""",
                    (session_id, session_id, cutoff),
                )
            except Exception as e:
                logger.warning(f"Error purging stale vectors from vec_findings: {e}")
