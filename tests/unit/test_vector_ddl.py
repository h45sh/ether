"""Unit tests for sqlite-vec extension integration and DDL in GraphStore."""

import pytest
import sqlite_vec

from ether.graph.store import GraphStore


@pytest.mark.asyncio
async def test_sqlite_vec_extension_loaded_and_table_created():
    """Verify that sqlite-vec extension loads and vec_findings table is ready."""
    store = GraphStore(":memory:")
    await store.initialize()

    async with store._get_conn() as db:
        # Check sqlite-vec version function works
        cursor = await db.execute("SELECT vec_version()")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0].startswith("v0.")

        # Check vec_findings virtual table exists
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='vec_findings'"
        )
        tbl = await cursor.fetchone()
        assert tbl is not None
        assert tbl[0] == "vec_findings"

        # Test insert and k-NN cosine distance query partitioned by session_id
        test_vec = [0.1] * 384
        serialized = sqlite_vec.serialize_float32(test_vec)
        await db.execute(
            "INSERT INTO vec_findings(session_id, node_id, embedding) VALUES (?, ?, ?)",
            ("test-sess-1", "test-node-1", serialized),
        )
        await db.commit()

        cursor = await db.execute(
            "SELECT node_id, distance FROM vec_findings WHERE embedding MATCH ? AND session_id = ? AND k = 1",
            (serialized, "test-sess-1"),
        )
        result = await cursor.fetchone()
        assert result is not None
        assert result[0] == "test-node-1"
        assert abs(result[1]) < 1e-4

    await store.close()
