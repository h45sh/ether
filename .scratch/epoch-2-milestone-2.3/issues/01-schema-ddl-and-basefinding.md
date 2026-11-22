# 01: Database DDL Schema Extensions & BaseFinding Model Update

**What to build:**
Update `SCHEMA_DDL` in `src/ether/graph/store.py` to add `observation_count INTEGER DEFAULT 1`, `ttl_seconds INTEGER DEFAULT 3600`, `anchor_hash TEXT`, and `last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP` directly to the `nodes` table, alongside indexes `idx_nodes_anchor`, `idx_nodes_status`, and `idx_nodes_last_seen`. Update `upsert_findings_batch()` and `upsert_finding()` to persist these fields, incrementing `observation_count` and refreshing `last_seen_at` on re-observation. Update `BaseFinding` in `src/ether/schemas/base.py` to support `status: Literal["proposed", "confirmed", "flapping", "stale"] = "confirmed"`, `ttl_seconds: int = 3600`, `anchor_hash: Optional[str] = None`, and `last_seen_at: datetime`. Write unit tests in `tests/unit/test_engine_store.py`.

**Blocked by:** None (can start immediately)

**Status:** completed

- [x] Update `SCHEMA_DDL` in `src/ether/graph/store.py` with temporal and anchor columns and indexes
- [x] Update `BaseFinding` in `src/ether/schemas/base.py` with `status`, `ttl_seconds`, `anchor_hash`, `last_seen_at`
- [x] Update `GraphStore.upsert_findings_batch()` to insert and update temporal columns (`observation_count++`, `last_seen_at = CURRENT_TIMESTAMP`)
- [x] Add unit tests verifying schema creation, column persistence, and observation increments in `tests/unit/test_engine_store.py`
