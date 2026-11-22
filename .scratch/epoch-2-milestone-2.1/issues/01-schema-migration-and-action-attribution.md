# 01: Schema Auto-Migration and Action Attribution

**What to build:**
Enable non-destructive database evolution and action attribution across Ether's storage layer. When `GraphStore.initialize()` runs, inspect the SQLite schema via `PRAGMA table_info` and automatically add `action_id TEXT` and `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP` to `nodes` and `edges` if missing. Update `upsert_node` and `add_edge` to accept an optional `action_id: Optional[str] = None` and record it. Add `mcp>=1.0.0` to project dependencies in `pyproject.toml`.

**Blocked by:** None (can start immediately)

**Status:** completed

- [x] Add `mcp>=1.0.0` to `dependencies` in `pyproject.toml`
- [x] Implement non-destructive `PRAGMA table_info` column inspection in `GraphStore.initialize()`
- [x] Add `action_id TEXT` and `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP` to `nodes` and `edges` in `SCHEMA_DDL` and runtime migration
- [x] Update `upsert_node` and `add_edge` in `GraphStore` to accept and persist `action_id`
- [x] Wire `action_id` propagation in `ActionGateway` when storing findings
- [x] Add unit tests in `tests/unit/test_storage.py` verifying backward compatibility and action attribution
