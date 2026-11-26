# PROTECTED FILE — See docs/CONTRIBUTING.md before modifying.
# Changes to this file require team agreement.
"""SQLite-based graph store for workspaces and sessions."""

import asyncio
import functools
import hashlib
import json
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import aiosqlite

try:
    import sqlite_vec
except ImportError:
    sqlite_vec = None

from ether.graph.decay import TemporalDecayEngine
from ether.graph.identity import IdentityAnchoringEngine
from ether.graph.merger import _hydrate_node_row
from ether.graph.timeline import ActionTimelineRepository
from ether.graph.vector_index import VectorIndex
from ether.graph.write_queue import UpsertResult, WriteQueue
from ether.schemas.base import BaseFinding
from ether.schemas.power import ActionRequest

logger = logging.getLogger(__name__)

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE',
    closed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE',
    closed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS nodes (
    session_id TEXT NOT NULL,
    id TEXT NOT NULL,
    schema_type TEXT NOT NULL,
    pik_json TEXT NOT NULL,
    data_json TEXT NOT NULL,
    status TEXT DEFAULT 'confirmed',
    action_id TEXT,
    created_action_id TEXT,
    observation_count INTEGER DEFAULT 1,
    ttl_seconds INTEGER DEFAULT 3600,
    anchor_hash TEXT,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, id),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS edges (
    session_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    action_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, source_id, target_id, relation_type),
    FOREIGN KEY (session_id, source_id) REFERENCES nodes(session_id, id) ON DELETE CASCADE,
    FOREIGN KEY (session_id, target_id) REFERENCES nodes(session_id, id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action_payload TEXT,
    result_payload TEXT,
    human_readable TEXT,
    schema_type TEXT,
    finding_json TEXT,
    closed INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notes (
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    content TEXT DEFAULT '',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (scope_type, scope_id)
);
CREATE TABLE IF NOT EXISTS node_beliefs (
    session_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    is_honeypot INTEGER NOT NULL DEFAULT 0,
    is_tarpit INTEGER NOT NULL DEFAULT 0,
    indicators TEXT NOT NULL DEFAULT '[]',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, node_id),
    FOREIGN KEY (session_id, node_id) REFERENCES nodes(session_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_node_beliefs_session ON node_beliefs(session_id);
CREATE INDEX IF NOT EXISTS idx_node_beliefs_confidence ON node_beliefs(session_id, confidence);
CREATE INDEX IF NOT EXISTS idx_nodes_session_schema ON nodes(session_id, schema_type);
CREATE INDEX IF NOT EXISTS idx_nodes_anchor ON nodes(session_id, anchor_hash);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(session_id, status);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(session_id, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_edges_session ON edges(session_id);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(session_id, source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(session_id, target_id);
CREATE INDEX IF NOT EXISTS idx_event_log_session_time ON event_log(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_ws_status ON sessions(workspace_id, status);
CREATE INDEX IF NOT EXISTS idx_workspaces_status ON workspaces(status);
CREATE INDEX IF NOT EXISTS idx_notes_scope ON notes(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_nodes_session_updated ON nodes(session_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_session_action ON nodes(session_id, action_id);
CREATE INDEX IF NOT EXISTS idx_edges_session_action ON edges(session_id, action_id);
CREATE VIRTUAL TABLE IF NOT EXISTS vec_findings USING vec0(
    id text primary key,
    session_id text partition key,
    node_id text,
    embedding float[384] distance_metric=cosine
);
"""


@functools.lru_cache(maxsize=4096)
def _cached_node_id(schema_type: str, pik_items: tuple) -> str:
    """Compute and cache deterministic SHA-256 node ID from sorted PIK items."""
    pik_str = json.dumps(dict(pik_items), sort_keys=True)
    return hashlib.sha256(f"{schema_type}:{pik_str}".encode()).hexdigest()


class GraphStore:
    """Manages workspaces, sessions, and stateful entity graphs."""

    def __init__(
        self,
        db_path: str,
        crypto_engine: Optional[Any] = None,
        sqlcipher_enabled: bool = False,
        settings: Optional[Any] = None,
    ):
        self.db_path = db_path
        self._settings = settings
        if crypto_engine is None and settings is not None and db_path != ":memory:":
            if getattr(getattr(settings, "graph", None), "encrypt_at_rest", False):
                from ether.graph.crypto import CryptoEngine

                data_dir = getattr(getattr(settings, "paths", None), "data_dir", None)
                crypto_engine = CryptoEngine(CryptoEngine.resolve_master_key(data_dir=data_dir))
        self._crypto_engine = crypto_engine
        self._on_upsert_callbacks: List[Callable[[str, BaseFinding], Any]] = []
        self._on_batch_callbacks: List[Callable[[str, List[BaseFinding]], Any]] = []
        self._conn: Optional[aiosqlite.Connection] = None
        self._lock: Optional[asyncio.Lock] = None
        self._closed: bool = False
        self._closing: bool = False
        self._session_bloom: Dict[str, Any] = {}
        self._session_status_cache: Dict[str, str] = {}
        self._warmed_sessions: Set[str] = set()
        self.timeline = ActionTimelineRepository(self)
        batch_win = getattr(getattr(settings, "graph", None), "write_batch_window_sec", 0.001)
        max_batch = getattr(getattr(settings, "graph", None), "write_max_batch_size", 500)
        self.write_worker = WriteQueue(
            self._get_conn,
            batch_window_seconds=batch_win,
            max_batch_size=max_batch,
        )
        self.vector_index = VectorIndex()
        self._read_pool: List[aiosqlite.Connection] = []
        self._read_pool_lock: Optional[asyncio.Lock] = None

    @property
    def _write_queue(self) -> Optional[asyncio.Queue]:
        return self.write_worker.queue

    @property
    def _writer_task(self) -> Optional[asyncio.Task]:
        return self.write_worker.task

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _get_bloom(self, session_id: str):
        """Get or initialize in-memory Bloom filter for fast node ID pre-filtering."""
        from ether.common.algorithms import BloomFilter

        if session_id not in self._session_bloom:
            self._session_bloom[session_id] = BloomFilter(capacity=25000, error_rate=0.01)
        return self._session_bloom[session_id]

    def on_upsert(self, callback):
        """Register an async callback to fire when any finding is upserted."""
        self._on_upsert_callbacks.append(callback)

    def on_findings_batch(self, callback):
        """Register an async callback to fire when a batch of findings is upserted."""
        self._on_batch_callbacks.append(callback)

    @asynccontextmanager
    async def _get_conn(self):
        """Helper to get a connection, supporting persistent connection for all paths."""
        if self._closed:
            raise ValueError("Cannot operate on a closed database.")
        async with self._get_lock():
            if self._conn is None:
                if self.db_path != ":memory:":
                    db_dir = os.path.dirname(os.path.abspath(self.db_path))
                    if db_dir:
                        os.makedirs(db_dir, mode=0o700, exist_ok=True)
                        try:
                            os.chmod(db_dir, 0o700)
                        except OSError:
                            pass
                    if not os.path.exists(self.db_path):
                        try:
                            fd = os.open(self.db_path, os.O_CREAT | os.O_WRONLY, 0o600)
                            os.close(fd)
                        except OSError:
                            pass
                self._conn = await aiosqlite.connect(self.db_path)
                await self.vector_index.load_extension(self._conn)
                await self._conn.execute("PRAGMA foreign_keys = ON")
                await self._conn.execute("PRAGMA trusted_schema = OFF")
                await self._conn.execute("PRAGMA busy_timeout = 5000")
                if self.db_path != ":memory:":
                    await self._conn.execute("PRAGMA journal_mode = WAL")
                    await self._conn.execute("PRAGMA synchronous = NORMAL")
                if self.db_path != ":memory:" and os.path.exists(self.db_path):
                    try:
                        os.chmod(self.db_path, 0o600)
                    except OSError:
                        pass
                cursor = await self._conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sessions' LIMIT 1"
                )
                if not await cursor.fetchone():
                    await self._conn.executescript(SCHEMA_DDL)
                    await self._conn.commit()
            yield self._conn

    def get_read_conn(self):
        """Acquire a read-only database connection context manager from the reader pool."""
        return self._get_read_conn()

    async def run_write_operation(
        self,
        func: Callable[..., Any],
        *args: Any,
        session_id: Optional[str] = None,
        enforce_open: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Serialize a mutation through WriteQueueWorker with centralized CLOSED-session sealing."""
        return await self._run_write(
            func, *args, session_id=session_id, enforce_open=enforce_open, **kwargs
        )

    async def initialize(self):
        """Create tables and indices if they don't exist."""
        self._ensure_writer_started()
        async with self._get_conn() as db:
            cursor = await db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='vec_findings'"
            )
            row = await cursor.fetchone()
            if (
                row
                and row[0]
                and ("session_id" not in row[0] or "id text primary key" not in row[0].lower())
            ):
                await db.execute("DROP TABLE IF EXISTS vec_findings")
            await db.executescript(SCHEMA_DDL)
            await db.commit()

    async def check_integrity(self) -> tuple[str, list[str]]:
        """Run an SQLite integrity check and return status and table list."""
        async with self._get_read_conn() as db:
            cursor = await db.execute("PRAGMA integrity_check")
            row = await cursor.fetchone()
            integrity_status = row[0] if row else "unknown"

            cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in await cursor.fetchall()]
            return integrity_status, tables

    def _get_read_pool_lock(self) -> asyncio.Lock:
        if self._read_pool_lock is None:
            self._read_pool_lock = asyncio.Lock()
        return self._read_pool_lock

    @asynccontextmanager
    async def _get_read_conn(self):
        """Acquire a read-only database connection from pool or fallback to primary in memory."""
        if self._closed:
            raise ValueError("Cannot operate on a closed database.")
        if self.db_path == ":memory:":
            async with self._get_conn() as conn:
                yield conn
            return

        if self._conn is None:
            async with self._get_conn():
                pass

        conn = None
        async with self._get_read_pool_lock():
            if self._read_pool:
                conn = self._read_pool.pop()

        if conn is None:
            conn = await aiosqlite.connect(self.db_path)
            await conn.execute("PRAGMA query_only = ON")
            await conn.execute("PRAGMA busy_timeout = 5000")
            await self.vector_index.load_extension(conn)

        try:
            yield conn
        finally:
            if not self._closed and not self._closing:
                async with self._get_read_pool_lock():
                    if len(self._read_pool) < 10:
                        self._read_pool.append(conn)
                    else:
                        await conn.close()
            else:
                await conn.close()

    def _ensure_writer_started(self) -> None:
        self.write_worker.ensure_started()

    async def _enqueue_write(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await self.write_worker.enqueue(func, *args, **kwargs)

    async def _run_write(
        self,
        func: Callable[..., Any],
        *args: Any,
        session_id: Optional[str] = None,
        enforce_open: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Serialize a mutation through WriteQueueWorker with centralized CLOSED-session sealing."""

        async def _guarded(db: aiosqlite.Connection) -> Any:
            if session_id is not None and enforce_open:
                st = self._session_status_cache.get(session_id)
                if st is None:
                    cursor = await db.execute(
                        "SELECT status FROM sessions WHERE id = ? LIMIT 1",
                        (session_id,),
                    )
                    row = await cursor.fetchone()
                    st = row[0] if row else "ACTIVE"
                    self._session_status_cache[session_id] = st
                if st == "CLOSED":
                    raise PermissionError(
                        f"Session '{session_id}' is forensically sealed and closed."
                    )
            return await func(db, *args, **kwargs)

        return await self._enqueue_write(_guarded)

    async def close(self):
        """Close the database cleanly, draining all pending operations."""
        self._closing = True

        # 1. Drain pending write queue operations
        await self.write_worker.close()

        self._closed = True

        # 2. Close reader pool
        if self._read_pool:
            for r_conn in self._read_pool:
                try:
                    await r_conn.close()
                except Exception:
                    pass
            self._read_pool.clear()

        # 3. Close primary persistent connection
        if self._conn:
            try:
                await self._conn.close()
            except Exception:
                pass
            self._conn = None

    async def get_or_create_workspace_session(
        self, workspace_name: str = "Default Workspace", session_name: str = "Default Session"
    ) -> tuple[str, str]:
        """Ensure a named workspace and session exist and return their IDs (ws_id, sess_id)."""

        async def _op(db: aiosqlite.Connection) -> tuple[str, str]:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT id FROM workspaces WHERE name = ? LIMIT 1",
                (workspace_name,),
            )
            row = await cursor.fetchone()
            if row:
                ws_id = row["id"]
            else:
                ws_id = str(uuid.uuid4())
                await db.execute(
                    "INSERT INTO workspaces (id, name, status) VALUES (?, ?, ?)",
                    (ws_id, workspace_name, "SYSTEM"),
                )

            cursor = await db.execute(
                "SELECT id FROM sessions WHERE workspace_id = ? AND name = ? LIMIT 1",
                (ws_id, session_name),
            )
            row = await cursor.fetchone()
            if row:
                sess_id = row["id"]
            else:
                sess_id = str(uuid.uuid4())
                await db.execute(
                    "INSERT INTO sessions (id, workspace_id, name, status) VALUES (?, ?, ?, ?)",
                    (sess_id, ws_id, session_name, "SYSTEM"),
                )

            return ws_id, sess_id

        return await self._run_write(_op)

    async def get_or_create_default_session(self) -> tuple[str, str]:
        """Ensure the default workspace and session exist and return their IDs (ws_id, sess_id)."""
        return await self.get_or_create_workspace_session("Default Workspace", "Default Session")

    async def get_or_create_learning_sandbox(self) -> tuple[str, str]:
        """Ensure the singleton Learning Sandbox and its session exist and return their IDs."""
        return await self.get_or_create_workspace_session("Learning Sandbox", "Guided Session")

    # --- Workspace Management ---

    async def create_workspace(self, name: str) -> str:
        workspace_id = str(uuid.uuid4())

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "INSERT INTO workspaces (id, name) VALUES (?, ?)", (workspace_id, name)
            )

        await self._run_write(_op)
        return workspace_id

    async def rename_workspace(self, workspace_id: str, new_name: str) -> None:
        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "UPDATE workspaces SET name = ? WHERE id = ?", (new_name, workspace_id)
            )

        await self._run_write(_op)

    async def list_workspaces(self, status_filter: Optional[str] = None) -> List[Dict]:
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            if status_filter:
                cursor = await db.execute(
                    "SELECT * FROM workspaces WHERE status = ? ORDER BY created_at DESC",
                    (status_filter,),
                )
            else:
                cursor = await db.execute("SELECT * FROM workspaces ORDER BY created_at DESC")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_workspace(self, workspace_id: str) -> Optional[Dict]:
        """Get workspace metadata."""
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def close_workspace(self, workspace_id: str) -> None:
        """Mark workspace as closed/archived."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "UPDATE workspaces SET status = 'CLOSED', closed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (workspace_id,),
            )

        await self._run_write(_op)

    async def reopen_workspace(self, workspace_id: str) -> None:
        """Reopen a closed workspace."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "UPDATE workspaces SET status = 'ACTIVE', closed_at = NULL WHERE id = ?",
                (workspace_id,),
            )

        await self._run_write(_op)

    # --- Session Management ---

    async def create_session(
        self, workspace_id: str, name: str, session_id: Optional[str] = None
    ) -> str:
        actual_session_id = session_id or str(uuid.uuid4())

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "INSERT INTO sessions (id, workspace_id, name) VALUES (?, ?, ?)",
                (actual_session_id, workspace_id, name),
            )

        await self._run_write(_op)
        return actual_session_id

    async def rename_session(self, session_id: str, new_name: str) -> None:
        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute("UPDATE sessions SET name = ? WHERE id = ?", (new_name, session_id))

        await self._run_write(_op, session_id=session_id)

    async def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session metadata."""
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def list_sessions(
        self, workspace_id: str, status_filter: Optional[str] = None
    ) -> List[Dict]:
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            if status_filter:
                cursor = await db.execute(
                    "SELECT * FROM sessions WHERE workspace_id = ? AND status = ? ORDER BY created_at DESC",
                    (workspace_id, status_filter),
                )
            else:
                cursor = await db.execute(
                    "SELECT * FROM sessions WHERE workspace_id = ? ORDER BY created_at DESC",
                    (workspace_id,),
                )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def list_all_sessions(self, status_filter: Optional[str] = None) -> List[Dict]:
        """List all sessions across all workspaces ordered by creation time descending."""
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            if status_filter:
                cursor = await db.execute(
                    "SELECT * FROM sessions WHERE status = ? ORDER BY created_at DESC",
                    (status_filter,),
                )
            else:
                cursor = await db.execute("SELECT * FROM sessions ORDER BY created_at DESC")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    def _hydrate_row(self, row: aiosqlite.Row) -> Dict[str, Any]:
        """Hydrate a node row and transparently decrypt fields when CryptoEngine is active."""
        hydrated = _hydrate_node_row(row)
        if self._crypto_engine is not None and isinstance(hydrated.get("data"), dict):
            hydrated["data"] = self._crypto_engine.decrypt_finding_data(
                hydrated.get("schema_type", ""), hydrated["data"]
            )
        return hydrated

    async def _mark_session_closed_sql(self, session_id: str) -> None:
        """Persist CLOSED session state via WriteQueue."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "UPDATE sessions SET status = 'CLOSED', closed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (session_id,),
            )

        self._session_status_cache[session_id] = "CLOSED"
        await self._run_write(_op, session_id=session_id, enforce_open=False)

    async def close_session(self, session_id: str) -> None:
        """Atomically seal session via two-phase SessionSealer and mark CLOSED."""
        from ether.common.session_sealer import SessionSealer

        sealer = SessionSealer(store=self)
        await sealer.seal_session(session_id)

    async def is_session_closed(self, session_id: str) -> bool:
        """Check if a session is forensically closed."""
        session = await self.get_session(session_id)
        return bool(session and session.get("status") == "CLOSED")

    async def reopen_session(self, session_id: str) -> None:
        """Reopen an archived session back to ACTIVE."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "UPDATE sessions SET status = 'ACTIVE', closed_at = NULL WHERE id = ?",
                (session_id,),
            )

        self._session_status_cache[session_id] = "ACTIVE"
        await self._run_write(_op, session_id=session_id, enforce_open=False)

    async def delete_workspace(self, workspace_id: str):
        """Delete a workspace and all its sessions/graphs (cascade)."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute("PRAGMA foreign_keys = ON")
            await self.vector_index.delete_workspace_vectors(db, workspace_id)
            await db.execute(
                """
                DELETE FROM notes
                WHERE scope_type IN ('session', 'learning')
                  AND scope_id IN (SELECT id FROM sessions WHERE workspace_id = ?)
                """,
                (workspace_id,),
            )
            await db.execute(
                "DELETE FROM notes WHERE scope_type = 'workspace' AND scope_id = ?",
                (workspace_id,),
            )
            await db.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))

        await self._run_write(_op)

    async def delete_session(self, session_id: str):
        """Delete a single session, its graph data, and its notes."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute("PRAGMA foreign_keys = ON")
            await self.vector_index.delete_session_vectors(db, session_id)
            await db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            await db.execute(
                "DELETE FROM notes WHERE (scope_type = 'session' AND scope_id = ?) OR (scope_type = 'learning' AND scope_id = ?)",
                (session_id, session_id),
            )

        await self._run_write(_op, session_id=session_id, enforce_open=False)

    # --- Notes Management ---

    async def get_notes(self, scope_type: str, scope_id: str) -> str:
        """Fetch persistent notes for a specific scope (e.g. 'session' or 'learning')."""
        async with self._get_read_conn() as db:
            cursor = await db.execute(
                "SELECT content FROM notes WHERE scope_type = ? AND scope_id = ?",
                (scope_type, str(scope_id)),
            )
            row = await cursor.fetchone()
            return row[0] if row and row[0] is not None else ""

    async def save_notes(self, scope_type: str, scope_id: str, content: str) -> None:
        """Atomically persist notes for a specific scope in SQLite."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                """
                INSERT INTO notes (scope_type, scope_id, content, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(scope_type, scope_id) DO UPDATE SET
                    content = excluded.content,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (scope_type, str(scope_id), content),
            )

        target_session_id = str(scope_id) if scope_type in ("session", "learning") else None
        await self._run_write(_op, session_id=target_session_id)

    async def move_session(self, session_id: str, target_workspace_id: str):
        """Move a session to a different workspace."""

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute(
                "UPDATE sessions SET workspace_id = ? WHERE id = ?",
                (target_workspace_id, session_id),
            )

        await self._run_write(_op, session_id=session_id)

    async def get_recent_activity(self, workspace_id: str, limit: int = 5) -> List[Dict]:
        """Fetch latest events across all sessions in a workspace."""
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            query = """
                SELECT e.*, s.name as session_name
                FROM event_log e
                JOIN sessions s ON e.session_id = s.id
                WHERE s.workspace_id = ? AND (e.closed IS NULL OR e.closed = 0)
                ORDER BY e.timestamp DESC LIMIT ?
            """
            cursor = await db.execute(query, (workspace_id, limit))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    # --- Graph Data Persistence (Session Aware) ---

    def generate_node_id(self, schema_type: str, pik: Dict[str, Any]) -> str:
        """Deterministically compute entity node ID from schema type and primary identity keys."""
        try:
            items = tuple(sorted(pik.items()))
            return _cached_node_id(schema_type, items)
        except TypeError:
            pik_str = json.dumps(pik, sort_keys=True)
            return hashlib.sha256(f"{schema_type}:{pik_str}".encode()).hexdigest()

    async def upsert_findings_batch(
        self, session_id: str, findings: List[BaseFinding], action_id: Optional[str] = None
    ) -> List[str]:
        """Atomically upsert a batch of findings in a single SQLite transaction."""
        if not findings:
            return []

        if self._session_status_cache.get(session_id) == "CLOSED":
            raise PermissionError(f"Session '{session_id}' is forensically sealed and closed.")

        result: UpsertResult = await self.write_worker.enqueue_upsert(
            session_id,
            findings,
            action_id=action_id,
            upsert_fn=self._raw_upsert_findings_batch,
        )
        node_ids = result.node_ids
        unique_node_ids = result.unique_node_ids
        parent_nodes = result.parent_nodes
        assoc_nodes = result.assoc_nodes

        bloom = self._get_bloom(session_id)
        # Update Bloom filter with all newly upserted node IDs and relationship nodes
        for nid in unique_node_ids:
            bloom.add(nid)
        for p_nid in parent_nodes:
            bloom.add(p_nid)
        for a_nid in assoc_nodes:
            bloom.add(a_nid)

        # Trigger reactive callbacks
        if self._on_batch_callbacks and findings:
            for cb in self._on_batch_callbacks:
                try:
                    await cb(session_id, findings)
                except Exception as e:
                    logger.error(
                        f"Error in reactive batch callback {getattr(cb, '__name__', 'callback')}: {e}"
                    )

        if self._on_upsert_callbacks and findings:
            for finding in findings:
                for upsert_cb in self._on_upsert_callbacks:
                    try:
                        await upsert_cb(session_id, finding)
                    except Exception as e:
                        logger.error(
                            f"Error in reactive callback {getattr(upsert_cb, '__name__', 'callback')}: {e}"
                        )

        return node_ids

    async def _raw_upsert_findings_batch(
        self,
        db: aiosqlite.Connection,
        session_id: str,
        findings: List[BaseFinding],
        action_id: Optional[str] = None,
    ) -> tuple[List[str], List[str], Dict[str, tuple], Dict[str, tuple]]:
        st = self._session_status_cache.get(session_id)
        if st is None:
            cursor = await db.execute(
                "SELECT status FROM sessions WHERE id = ? LIMIT 1", (session_id,)
            )
            row = await cursor.fetchone()
            st = row[0] if row else "ACTIVE"
            self._session_status_cache[session_id] = st
        if st == "CLOSED":
            raise PermissionError(f"Session '{session_id}' is forensically sealed and closed.")
        node_ids: List[str] = []
        event_log_params = []
        unique_node_ids: List[str] = []
        seen = set()
        node_metadata: Dict[str, Dict[str, Any]] = {}

        parent_nodes: Dict[str, tuple] = {}
        parent_edges: set = set()
        assoc_nodes: Dict[str, tuple] = {}
        assoc_edges: set = set()

        for finding in findings:
            node_id = self.generate_node_id(finding.schema_type, finding.pik)
            node_ids.append(node_id)

            event_log_params.append(
                (
                    session_id,
                    finding.schema_type,
                    finding.model_dump_json(),
                    f"Discovered {finding.schema_type}",
                    "{}",
                    "{}",
                )
            )

            anchor_hash = IdentityAnchoringEngine.extract_anchor_hash(finding)
            ttl_seconds = getattr(finding, "ttl_seconds", 3600) or 3600

            if node_id not in seen:
                seen.add(node_id)
                unique_node_ids.append(node_id)
                node_metadata[node_id] = {
                    "schema_type": finding.schema_type,
                    "pik": finding.pik,
                    "data": dict(finding.data),
                    "status": finding.status,
                    "ttl_seconds": ttl_seconds,
                    "anchor_hash": anchor_hash,
                }
            else:
                from ether.graph.merger import NodeAttributeMerger

                node_metadata[node_id]["data"] = NodeAttributeMerger.merge_node_data(
                    node_metadata[node_id]["data"], finding.data
                )
                node_metadata[node_id]["status"] = finding.status
                node_metadata[node_id]["ttl_seconds"] = ttl_seconds
                if anchor_hash:
                    node_metadata[node_id]["anchor_hash"] = anchor_hash

            if finding.parent:
                p = finding.parent
                parent_id = self.generate_node_id(p.target_type, p.target_pik)
                parent_nodes[parent_id] = (
                    session_id,
                    parent_id,
                    p.target_type,
                    json.dumps(p.target_pik),
                    "{}",
                )
                parent_edges.add((session_id, parent_id, node_id, p.via))
            else:
                # Deterministic automatic edge wiring (Ticket 08)
                if finding.schema_type == "network.service":
                    hip = finding.pik.get("host_ip") or finding.data.get("host_ip") or finding.pik.get("ip")
                    if hip:
                        p_id = self.generate_node_id("network.host", {"ip": hip})
                        parent_nodes[p_id] = (session_id, p_id, "network.host", json.dumps({"ip": hip}), "{}")
                        parent_edges.add((session_id, p_id, node_id, "hosts_service"))
                elif finding.schema_type == "web.endpoint":
                    hip = finding.data.get("host_ip") or finding.pik.get("host_ip")
                    port = finding.data.get("port") or finding.pik.get("port")
                    if hip and port:
                        svc_pik = {"host_ip": hip, "port": int(port), "protocol": "tcp"}
                        p_id = self.generate_node_id("network.service", svc_pik)
                        parent_nodes[p_id] = (session_id, p_id, "network.service", json.dumps(svc_pik), "{}")
                        parent_edges.add((session_id, p_id, node_id, "hosts_endpoint"))
                elif finding.schema_type in ("vulnerability", "cve"):
                    hip = finding.data.get("host_ip") or finding.pik.get("host_ip") or finding.data.get("ip")
                    port = finding.data.get("port") or finding.pik.get("port")
                    url = finding.data.get("url") or finding.pik.get("url")
                    if url:
                        ep_id = self.generate_node_id("web.endpoint", {"url": url})
                        parent_nodes[ep_id] = (session_id, ep_id, "web.endpoint", json.dumps({"url": url}), "{}")
                        parent_edges.add((session_id, ep_id, node_id, "has_vulnerability"))
                    elif hip and port:
                        svc_pik = {"host_ip": hip, "port": int(port), "protocol": "tcp"}
                        p_id = self.generate_node_id("network.service", svc_pik)
                        parent_nodes[p_id] = (session_id, p_id, "network.service", json.dumps(svc_pik), "{}")
                        parent_edges.add((session_id, p_id, node_id, "has_vulnerability"))
                    elif hip:
                        p_id = self.generate_node_id("network.host", {"ip": hip})
                        parent_nodes[p_id] = (session_id, p_id, "network.host", json.dumps({"ip": hip}), "{}")
                        parent_edges.add((session_id, p_id, node_id, "has_vulnerability"))

            for assoc in finding.associations:
                assoc_id = self.generate_node_id(assoc.target_type, assoc.target_pik)
                assoc_nodes[assoc_id] = (
                    session_id,
                    assoc_id,
                    assoc.target_type,
                    json.dumps(assoc.target_pik),
                    "{}",
                )
                assoc_edges.add((session_id, node_id, assoc_id, assoc.via))

        bloom = self._get_bloom(session_id)

        # Warm up bloom filter for this session if newly accessed
        if session_id not in self._warmed_sessions:
            cursor = await db.execute("SELECT id FROM nodes WHERE session_id = ?", (session_id,))
            rows = await cursor.fetchall()
            for (nid,) in rows:
                bloom.add(nid)
            self._warmed_sessions.add(session_id)

        # 1. Log the events in a single batch
        await db.executemany(
            """INSERT INTO event_log (session_id, schema_type, finding_json, human_readable, action_payload, result_payload)
               VALUES (?, ?, ?, ?, ?, ?)""",
            event_log_params,
        )

        # 2. Fetch existing data only for candidate node IDs that might exist in this session (via Bloom filter)
        candidate_ids = [nid for nid in unique_node_ids if nid in bloom]
        if candidate_ids:
            for i in range(0, len(candidate_ids), 500):
                chunk = candidate_ids[i : i + 500]
                placeholders = ",".join("?" for _ in chunk)
                query_parts = (
                    "SELECT id, data_json FROM nodes WHERE session_id = ? AND id IN (",
                    placeholders,
                    ")",
                )
                select_sql = "".join(query_parts)
                cursor = await db.execute(select_sql, [session_id, *chunk])
                rows = await cursor.fetchall()
                for r_id, r_data in rows:
                    if r_data:
                        from ether.graph.merger import NodeAttributeMerger

                        merged = json.loads(r_data)
                        if self._crypto_engine is not None:
                            merged = self._crypto_engine.decrypt_finding_data(
                                node_metadata[r_id]["schema_type"], merged
                            )
                        node_metadata[r_id]["data"] = NodeAttributeMerger.merge_node_data(
                            merged, node_metadata[r_id]["data"]
                        )

        # 3. Batch upsert the nodes
        nodes_params = [
            (
                session_id,
                nid,
                meta["schema_type"],
                json.dumps(meta["pik"]),
                json.dumps(
                    self._crypto_engine.encrypt_finding_data(meta["schema_type"], meta["data"])
                    if self._crypto_engine is not None
                    else meta["data"]
                ),
                meta["status"],
                action_id,
                action_id,
                meta["ttl_seconds"],
                meta["anchor_hash"],
            )
            for nid, meta in node_metadata.items()
        ]
        await db.executemany(
            """INSERT INTO nodes (
                   session_id, id, schema_type, pik_json, data_json, status,
                   action_id, created_action_id, ttl_seconds, anchor_hash,
                   observation_count, last_seen_at
               )
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
               ON CONFLICT(session_id, id) DO UPDATE SET
                   data_json = excluded.data_json,
                   status = excluded.status,
                   action_id = COALESCE(excluded.action_id, nodes.action_id),
                   observation_count = nodes.observation_count + 1,
                   ttl_seconds = excluded.ttl_seconds,
                   anchor_hash = COALESCE(excluded.anchor_hash, nodes.anchor_hash),
                   last_seen_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP""",
            nodes_params,
        )

        # 4. Handle Parent and Association Relations (Auto-wiring in consolidated batches)
        rel_nodes = list(parent_nodes.values())
        if assoc_nodes:
            rel_nodes.extend(assoc_nodes.values())
        if rel_nodes:
            await db.executemany(
                """INSERT OR IGNORE INTO nodes (
                       session_id, id, schema_type, pik_json, data_json,
                       action_id, created_action_id, observation_count, ttl_seconds, last_seen_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 3600, CURRENT_TIMESTAMP)""",
                [(r[0], r[1], r[2], r[3], r[4], action_id, action_id) for r in rel_nodes],
            )

        # 4.5 Invariant Identity Anchoring & Cross-IP Migration
        (
            migration_edges,
            stale_migrated_node_ids,
            migration_event_params,
        ) = await IdentityAnchoringEngine.resolve_migrations(
            db, session_id, node_metadata, action_id
        )

        if stale_migrated_node_ids:
            placeholders = ",".join("?" for _ in stale_migrated_node_ids)
            await db.execute(
                f"UPDATE nodes SET status = 'stale', updated_at = CURRENT_TIMESTAMP WHERE session_id = ? AND id IN ({placeholders})",
                [session_id, *stale_migrated_node_ids],
            )

        if migration_event_params:
            await db.executemany(
                """INSERT INTO event_log (session_id, schema_type, finding_json, human_readable, action_payload, result_payload)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                migration_event_params,
            )

        rel_edges = list(parent_edges | assoc_edges | migration_edges)
        if rel_edges:
            await db.executemany(
                """INSERT INTO edges (session_id, source_id, target_id, relation_type, action_id)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(session_id, source_id, target_id, relation_type) DO UPDATE SET
                       action_id = COALESCE(excluded.action_id, edges.action_id),
                       updated_at = CURRENT_TIMESTAMP""",
                [(r[0], r[1], r[2], r[3], action_id) for r in rel_edges],
            )

        # 5. Vector Indexing in vec_findings (sqlite-vec)
        node_texts = []
        for finding in findings:
            nid = self.generate_node_id(finding.schema_type, finding.pik)
            try:
                node_texts.append((nid, finding.to_semantic_text()))
            except Exception:
                pass
        await self.vector_index.sync_node_embeddings(
            db, node_texts, session_id=session_id, existing_node_ids=set(candidate_ids)
        )

        return node_ids, unique_node_ids, parent_nodes, assoc_nodes

    async def upsert_finding(
        self, session_id: str, finding: BaseFinding, action_id: Optional[str] = None
    ) -> str:
        """Upsert a single finding (delegates to upsert_findings_batch)."""
        node_ids = await self.upsert_findings_batch(session_id, [finding], action_id=action_id)
        return node_ids[0] if node_ids else ""

    async def query(
        self,
        schema_type: str,
        session_id: Optional[str] = None,
        include_stale: bool = False,
    ) -> List[Dict]:
        """Fetch all nodes of a specific schema type."""
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            conditions = ["schema_type = ?"]
            params: list[Any] = [schema_type]
            if session_id:
                conditions.append("session_id = ?")
                params.append(session_id)
            if not include_stale:
                conditions.append("status != 'stale'")
            where_sql = " AND ".join(conditions)
            stmt = " ".join(["SELECT * FROM nodes WHERE", where_sql])
            cursor = await db.execute(stmt, params)
            rows = await cursor.fetchall()
            return [self._hydrate_row(r) for r in rows]

    async def get_event_log(self, session_id: str) -> List[Dict]:
        """Fetch all events for a session."""
        return await self.timeline.get_event_log(session_id)

    async def mark_event_closed(self, action_id: str, session_id: Optional[str] = None) -> None:
        """Mark an event log entry as closed/deleted."""
        await self.timeline.mark_event_closed(action_id, session_id)

    async def get_closed_events_count(self, session_id: str) -> int:
        """Get the count of closed events/tabs for a session."""
        return await self.timeline.get_closed_events_count(session_id)

    async def get_all_nodes(
        self, session_id: str, schema_type: Optional[str] = None, include_stale: bool = False
    ) -> List[Dict]:
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            query = "SELECT * FROM nodes WHERE session_id = ?"
            params: List[Any] = [session_id]
            if not include_stale:
                query += " AND status != 'stale'"
            if schema_type:
                query += " AND schema_type = ?"
                params.append(schema_type)
            query += " ORDER BY updated_at DESC"
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [self._hydrate_row(r) for r in rows]

    async def sync_vectors_batch(self, findings: List[BaseFinding], session_id: str = "") -> int:
        """Compute and store offline vector embeddings for a batch of findings in vec_findings."""

        async def _op(db: aiosqlite.Connection) -> int:
            return await self.vector_index.sync_findings_batch(
                db, findings, self.generate_node_id, session_id=session_id
            )

        return await self._run_write(_op, session_id=session_id or None)

    async def semantic_search(
        self,
        session_id: str,
        query: str,
        limit: int = 10,
        min_score: float = 0.0,
        schema_type: Optional[str] = None,
        include_stale: bool = False,
    ) -> List[Dict[str, Any]]:
        """Semantic search against session findings using offline vector embeddings.

        Args:
            session_id: Active session ID to scope the search.
            query: Natural language query (e.g. 'Apache HTTP Server path traversal').
            limit: Maximum number of findings to return.
            min_score: Minimum cosine similarity score [0.0, 1.0].
            schema_type: Optional filter by schema_type (e.g. 'network.service').
            include_stale: Whether to include findings from stale nodes.

        Returns:
            List of matching finding node dictionaries ordered by descending similarity,
            with added 'similarity' and 'distance' fields.
        """
        async with self._get_read_conn() as db:
            return await self.vector_index.semantic_search(
                db,
                session_id=session_id,
                query=query,
                limit=limit,
                min_score=min_score,
                schema_type=schema_type,
                include_stale=include_stale,
            )

    async def reconcile_state_decay(
        self, session_id: str, now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Deterministically evaluate and reconcile temporal state decay for a session."""

        async def _op(db: aiosqlite.Connection) -> Dict[str, Any]:
            return await TemporalDecayEngine.reconcile_state_decay(db, session_id, now=now)

        return await self._run_write(_op, session_id=session_id)

    async def prune_stale_nodes(
        self, session_id: str, max_age_seconds: int = 604800, now: Optional[datetime] = None
    ) -> int:
        """Permanently delete stale nodes and their cascading edges older than max_age_seconds."""

        async def _op(db: aiosqlite.Connection) -> int:
            return await TemporalDecayEngine.prune_stale_nodes(
                db, session_id, self.vector_index, max_age_seconds=max_age_seconds, now=now
            )

        return await self._run_write(_op, session_id=session_id)

    async def get_anchored_migrations(
        self,
        session_id: str,
        action_id: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Fetch anchored identity migrations recorded for a session."""
        async with self._get_read_conn() as db:
            return await IdentityAnchoringEngine.get_anchored_migrations(
                db, session_id, action_id=action_id
            )

    async def add_edges(
        self,
        session_id: str,
        edges: List[Tuple[str, str, str]],
        action_id: Optional[str] = None,
    ) -> None:
        """Insert relational edges (source_id, target_id, relation_type) into the graph for a session."""
        if not edges:
            return

        async def _insert_edges_op(db: aiosqlite.Connection) -> None:
            await db.executemany(
                """INSERT INTO edges (session_id, source_id, target_id, relation_type, action_id)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(session_id, source_id, target_id, relation_type) DO UPDATE SET
                       action_id = COALESCE(excluded.action_id, edges.action_id),
                       updated_at = CURRENT_TIMESTAMP""",
                [(session_id, r[0], r[1], r[2], action_id) for r in edges],
            )

        await self._run_write(_insert_edges_op, session_id=session_id)

    async def get_all_edges(self, session_id: str) -> List[Dict]:
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM edges WHERE session_id = ?", (session_id,))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_workspace_nodes(self, workspace_id: str) -> List[Dict]:
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """SELECT n.* FROM nodes n
                   JOIN sessions s ON n.session_id = s.id
                   WHERE s.workspace_id = ? ORDER BY n.updated_at DESC""",
                (workspace_id,),
            )
            rows = await cursor.fetchall()
            return [self._hydrate_row(r) for r in rows]

    async def get_workspace_edges(self, workspace_id: str) -> List[Dict]:
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """SELECT e.* FROM edges e
                   JOIN sessions s ON e.session_id = s.id
                   WHERE s.workspace_id = ?""",
                (workspace_id,),
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_node(self, session_id: str, node_id: str) -> Optional[Dict]:
        """Fetch a specific node by ID."""
        async with self._get_read_conn() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM nodes WHERE session_id = ? AND id = ?", (session_id, node_id)
            )
            row = await cursor.fetchone()
            return self._hydrate_row(row) if row else None

    async def update_node_data(
        self, session_id: str, node_id: str, updates: Dict[str, Any]
    ) -> None:
        """Update fields inside a node's data_json (such as custom alias, name, or notes)."""

        async def _op(db: aiosqlite.Connection) -> None:
            cursor = await db.execute(
                "SELECT data_json FROM nodes WHERE session_id = ? AND id = ?", (session_id, node_id)
            )
            row = await cursor.fetchone()
            if not row:
                return
            current_data = json.loads(row[0] or "{}")
            current_data.update(updates)
            await db.execute(
                "UPDATE nodes SET data_json = ? WHERE session_id = ? AND id = ?",
                (json.dumps(current_data), session_id, node_id),
            )

        await self._run_write(_op, session_id=session_id)

    async def get_stats(
        self, session_id: Optional[str] = None, workspace_id: Optional[str] = None
    ) -> Dict[str, int]:
        async with self._get_read_conn() as db:
            if session_id:
                cursor = await db.execute(
                    "SELECT schema_type, COUNT(*) FROM nodes WHERE session_id = ? GROUP BY schema_type",
                    (session_id,),
                )
            elif workspace_id:
                cursor = await db.execute(
                    """SELECT n.schema_type, COUNT(*)
                       FROM nodes n
                       JOIN sessions s ON n.session_id = s.id
                       WHERE s.workspace_id = ?
                       GROUP BY n.schema_type""",
                    (workspace_id,),
                )
            else:
                cursor = await db.execute(
                    "SELECT schema_type, COUNT(*) FROM nodes GROUP BY schema_type"
                )

            rows = await cursor.fetchall()
            stats = {"total": 0}
            for schema_type, count in rows:
                stats[schema_type] = count
                stats["total"] += count
            return stats

    async def append_event(
        self, session_id: str, action: ActionRequest, result: Dict[str, Any], message: str
    ):
        """Append a structured action/result event to the log."""
        await self.timeline.append_event(session_id, action, result, message)

    async def log_audit_event(
        self, session_id: str, action_name: str, message: str, status: str
    ) -> None:
        """Append an audit lifecycle event (e.g. session closed/reopened) to event_log."""
        await self.timeline.log_audit_event(session_id, action_name, message, status)

    async def export_session(self, session_id: str, dest_db_path: str) -> None:
        """Export session metadata, nodes, edges, and event_log rows to a new SQLite database."""
        dest_store = GraphStore(dest_db_path)
        await dest_store.initialize()
        await dest_store.close()

        async def _op(db: aiosqlite.Connection) -> None:
            await db.execute("ATTACH DATABASE ? AS dest", (dest_db_path,))
            try:
                # 1. Copy workspace row
                await db.execute(
                    """
                    INSERT OR IGNORE INTO dest.workspaces (id, name, status, created_at)
                    SELECT w.id, w.name, w.status, w.created_at
                    FROM workspaces w
                    JOIN sessions s ON s.workspace_id = w.id
                    WHERE s.id = ?
                """,
                    (session_id,),
                )

                # 2. Copy session row
                await db.execute(
                    """
                    INSERT OR IGNORE INTO dest.sessions (id, workspace_id, name, status, created_at)
                    SELECT id, workspace_id, name, status, created_at
                    FROM sessions
                    WHERE id = ?
                """,
                    (session_id,),
                )

                # 3. Copy nodes
                await db.execute(
                    """
                    INSERT OR IGNORE INTO dest.nodes (session_id, id, schema_type, pik_json, data_json, status, action_id, created_at, updated_at)
                    SELECT session_id, id, schema_type, pik_json, data_json, status, action_id, created_at, updated_at
                    FROM nodes
                    WHERE session_id = ?
                """,
                    (session_id,),
                )

                # 4. Copy edges
                await db.execute(
                    """
                    INSERT OR IGNORE INTO dest.edges (session_id, source_id, target_id, relation_type, action_id, created_at, updated_at)
                    SELECT session_id, source_id, target_id, relation_type, action_id, created_at, updated_at
                    FROM edges
                    WHERE session_id = ?
                """,
                    (session_id,),
                )

                # 5. Copy event_log
                await db.execute(
                    """
                    INSERT OR IGNORE INTO dest.event_log (id, session_id, timestamp, action_payload, result_payload, human_readable, schema_type, finding_json, closed)
                    SELECT id, session_id, timestamp, action_payload, result_payload, human_readable, schema_type, finding_json, closed
                    FROM event_log
                    WHERE session_id = ?
                """,
                    (session_id,),
                )

                # 6. Copy notes
                await db.execute(
                    """
                    INSERT OR IGNORE INTO dest.notes (scope_type, scope_id, content, updated_at)
                    SELECT scope_type, scope_id, content, updated_at
                    FROM notes
                    WHERE (scope_type = 'session' AND scope_id = ?)
                       OR (scope_type = 'learning' AND scope_id = ?)
                """,
                    (session_id, session_id),
                )

                await db.commit()
                if os.path.exists(dest_db_path):
                    try:
                        os.chmod(dest_db_path, 0o600)
                    except OSError:
                        pass
            except Exception:
                await db.rollback()
                raise
            finally:
                try:
                    await db.execute("DETACH DATABASE dest")
                except Exception:
                    pass

        await self.write_worker.enqueue_mutation(_op, transactional=False)

    async def import_session(
        self, src_db_path: str, target_workspace_id: Optional[str] = None
    ) -> str:
        """Import a session from an exported SQLite database into this store.

        If the session already exists, it is overwritten (restored).
        Returns the imported session ID.
        """
        async def _op(db: aiosqlite.Connection) -> str:
            db.row_factory = aiosqlite.Row
            await db.execute("ATTACH DATABASE ? AS src", (src_db_path,))
            try:
                cursor = await db.execute("SELECT * FROM src.sessions LIMIT 1")
                src_session = await cursor.fetchone()
                if not src_session:
                    raise ValueError("No session found in the source database.")

                src_session_id = src_session["id"]
                src_session_name = src_session["name"]
                src_session_status = src_session["status"]
                src_session_created = src_session["created_at"]

                cursor_ws = await db.execute(
                    "SELECT name FROM src.workspaces WHERE id = ?", (src_session["workspace_id"],)
                )
                ws_row = await cursor_ws.fetchone()
                src_workspace_name = ws_row["name"] if ws_row else "Imported Workspace"

                if target_workspace_id:
                    cursor_target_ws = await db.execute(
                        "SELECT id FROM workspaces WHERE id = ?", (target_workspace_id,)
                    )
                    t_ws = await cursor_target_ws.fetchone()
                    if not t_ws:
                        raise ValueError(f"Target workspace ID '{target_workspace_id}' not found.")
                    final_workspace_id = target_workspace_id
                else:
                    if src_workspace_name.lower() == "learning sandbox":
                        cursor_target_ws = await db.execute(
                            "SELECT id FROM workspaces WHERE LOWER(name) = 'learning sandbox' LIMIT 1"
                        )
                    else:
                        cursor_target_ws = await db.execute(
                            "SELECT id FROM workspaces WHERE LOWER(name) = ? AND status != 'SYSTEM' LIMIT 1",
                            (src_workspace_name.lower(),),
                        )
                    t_ws = await cursor_target_ws.fetchone()
                    if t_ws:
                        final_workspace_id = t_ws["id"]
                    else:
                        import uuid

                        final_workspace_id = str(uuid.uuid4())
                        await db.execute(
                            "INSERT INTO workspaces (id, name, status) VALUES (?, ?, 'ACTIVE')",
                            (final_workspace_id, src_workspace_name),
                        )

                # Check if the session already exists by ID in our database
                cursor_existing_sess = await db.execute(
                    "SELECT id, name, workspace_id FROM sessions WHERE id = ?", (src_session_id,)
                )
                existing_sess = await cursor_existing_sess.fetchone()

                if existing_sess:
                    # Clean up existing session data first to overwrite/restore it
                    await db.execute("DELETE FROM sessions WHERE id = ?", (src_session_id,))
                    # Explicit cleanup (cascades should handle this, but just to be sure)
                    await db.execute("DELETE FROM nodes WHERE session_id = ?", (src_session_id,))
                    await db.execute("DELETE FROM edges WHERE session_id = ?", (src_session_id,))
                    await db.execute(
                        "DELETE FROM event_log WHERE session_id = ?", (src_session_id,)
                    )

                # Handle name collision with a DIFFERENT session in the target workspace
                final_session_name = src_session_name
                collision_idx = 1
                while True:
                    cursor_sess = await db.execute(
                        "SELECT id FROM sessions WHERE workspace_id = ? AND LOWER(name) = ? AND id != ? LIMIT 1",
                        (final_workspace_id, final_session_name.lower(), src_session_id),
                    )
                    s_row = await cursor_sess.fetchone()
                    if not s_row:
                        break
                    final_session_name = f"{src_session_name} (Imported {collision_idx})"
                    collision_idx += 1

                await db.execute(
                    "INSERT INTO sessions (id, workspace_id, name, status, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        src_session_id,
                        final_workspace_id,
                        final_session_name,
                        src_session_status,
                        src_session_created,
                    ),
                )

                cursor_nodes = await db.execute(
                    "SELECT * FROM src.nodes WHERE session_id = ?", (src_session_id,)
                )
                nodes = await cursor_nodes.fetchall()
                nodes_to_insert = []
                for n in nodes:
                    schema_type = n["schema_type"]
                    if (
                        not schema_type
                        or not re.match(r"^[a-zA-Z0-9_.]+$", schema_type)
                        or len(schema_type) > 64
                    ):
                        raise ValueError(f"Invalid schema_type '{schema_type}' in imported node.")
                    try:
                        pik_val = json.loads(n["pik_json"])
                        data_val = json.loads(n["data_json"])
                        if not isinstance(pik_val, dict) or not isinstance(data_val, dict):
                            raise ValueError
                    except Exception:
                        raise ValueError(
                            f"Corrupt JSON payload in imported node {n['id']}."
                        ) from None

                    nodes_to_insert.append(
                        (
                            src_session_id,
                            n["id"],
                            schema_type,
                            json.dumps(pik_val),
                            json.dumps(data_val),
                            n["status"],
                            n["action_id"] if "action_id" in n.keys() else None,
                            n["created_at"] if "created_at" in n.keys() else n["updated_at"],
                            n["updated_at"],
                        )
                    )

                if nodes_to_insert:
                    await db.executemany(
                        """INSERT INTO nodes (session_id, id, schema_type, pik_json, data_json, status, action_id, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        nodes_to_insert,
                    )

                cursor_edges = await db.execute(
                    "SELECT * FROM src.edges WHERE session_id = ?", (src_session_id,)
                )
                edges = await cursor_edges.fetchall()
                if edges:
                    edges_to_insert = [
                        (
                            src_session_id,
                            e["source_id"],
                            e["target_id"],
                            e["relation_type"],
                            e["action_id"] if "action_id" in e.keys() else None,
                            e["created_at"] if "created_at" in e.keys() else None,
                            e["updated_at"] if "updated_at" in e.keys() else None,
                        )
                        for e in edges
                    ]
                    await db.executemany(
                        """INSERT INTO edges (session_id, source_id, target_id, relation_type, action_id, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), COALESCE(?, CURRENT_TIMESTAMP))""",
                        edges_to_insert,
                    )

                cursor_events = await db.execute(
                    "SELECT * FROM src.event_log WHERE session_id = ?", (src_session_id,)
                )
                events = await cursor_events.fetchall()
                if events:
                    events_to_insert = [
                        (
                            src_session_id,
                            ev["timestamp"],
                            ev["action_payload"],
                            ev["result_payload"],
                            ev["human_readable"],
                            ev["schema_type"],
                            ev["finding_json"],
                            ev["closed"],
                        )
                        for ev in events
                    ]
                    await db.executemany(
                        "INSERT INTO event_log (session_id, timestamp, action_payload, result_payload, human_readable, schema_type, finding_json, closed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        events_to_insert,
                    )

                # Import notes if present in src
                try:
                    cursor_notes = await db.execute(
                        "SELECT * FROM src.notes WHERE scope_id = ?", (src_session_id,)
                    )
                    notes_rows = await cursor_notes.fetchall()
                    if notes_rows:
                        notes_to_insert = [
                            (n["scope_type"], src_session_id, n["content"]) for n in notes_rows
                        ]
                        await db.executemany(
                            "INSERT OR REPLACE INTO notes (scope_type, scope_id, content) VALUES (?, ?, ?)",
                            notes_to_insert,
                        )
                except Exception:
                    pass

                await db.commit()
                return src_session_id
            except Exception:
                await db.rollback()
                raise
            finally:
                try:
                    await db.execute("DETACH DATABASE src")
                except Exception:
                    pass

        return await self.write_worker.enqueue_mutation(_op, transactional=False)

    async def upsert_node_belief(
        self,
        node_id: str,
        session_id: str,
        confidence: float = 1.0,
        is_honeypot: int = 0,
        is_tarpit: int = 0,
        indicators: Optional[List[str]] = None,
    ) -> None:
        """Upsert probabilistic belief score and deception indicators for a graph node."""
        await self.upsert_node_beliefs_batch(
            session_id,
            [
                {
                    "node_id": node_id,
                    "confidence": confidence,
                    "is_honeypot": is_honeypot,
                    "is_tarpit": is_tarpit,
                    "indicators": indicators or [],
                }
            ],
        )

    async def upsert_node_beliefs_batch(
        self,
        session_id: str,
        beliefs: List[Dict[str, Any]],
    ) -> None:
        """Batch upsert probabilistic belief scores and deception indicators for a session."""
        if not beliefs:
            return
        rows = [
            (
                session_id,
                b["node_id"],
                float(b.get("confidence", 1.0)),
                int(bool(b.get("is_honeypot", 0))),
                int(bool(b.get("is_tarpit", 0))),
                json.dumps(b.get("indicators") or []),
            )
            for b in beliefs
        ]

        async def _op(db: aiosqlite.Connection) -> None:
            await db.executemany(
                """
                INSERT INTO node_beliefs (session_id, node_id, confidence, is_honeypot, is_tarpit, indicators, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(session_id, node_id) DO UPDATE SET
                    confidence = excluded.confidence,
                    is_honeypot = excluded.is_honeypot,
                    is_tarpit = excluded.is_tarpit,
                    indicators = excluded.indicators,
                    updated_at = CURRENT_TIMESTAMP
                """,
                rows,
            )

        await self._run_write(_op, session_id=session_id)

    async def get_node_belief(self, session_id: str, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve belief details for a specific node."""
        async with self._get_read_conn() as db:
            cursor = await db.execute(
                """
                SELECT session_id, node_id, confidence, is_honeypot, is_tarpit, indicators, updated_at
                FROM node_beliefs
                WHERE session_id = ? AND node_id = ?
                """,
                (session_id, node_id),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return {
                "session_id": row[0],
                "node_id": row[1],
                "confidence": float(row[2]),
                "is_honeypot": bool(row[3]),
                "is_tarpit": bool(row[4]),
                "indicators": json.loads(row[5]) if row[5] else [],
                "updated_at": str(row[6]),
            }

    async def list_node_beliefs(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve all node beliefs for a session."""
        async with self._get_read_conn() as db:
            cursor = await db.execute(
                """
                SELECT session_id, node_id, confidence, is_honeypot, is_tarpit, indicators, updated_at
                FROM node_beliefs
                WHERE session_id = ?
                ORDER BY confidence ASC
                """,
                (session_id,),
            )
            rows = await cursor.fetchall()
            return [
                {
                    "session_id": r[0],
                    "node_id": r[1],
                    "confidence": float(r[2]),
                    "is_honeypot": bool(r[3]),
                    "is_tarpit": bool(r[4]),
                    "indicators": json.loads(r[5]) if r[5] else [],
                    "updated_at": str(r[6]),
                }
                for r in rows
            ]
