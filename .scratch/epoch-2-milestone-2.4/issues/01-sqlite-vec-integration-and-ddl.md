# 01: `sqlite-vec` Dependency & Extension Integration in `GraphStore`

**What to build:**
Add `sqlite-vec>=0.1.9` to `dependencies` in `pyproject.toml`. In `src/ether/graph/store.py`, enable extension loading on SQLite connections and load `sqlite-vec` extension (`sqlite_vec.loadable_path()`). Extend `SCHEMA_DDL` to create the `vec_findings` virtual table using `vec0`:
```sql
CREATE VIRTUAL TABLE IF NOT EXISTS vec_findings USING vec0(
    node_id text primary key,
    embedding float[384] distance_metric=cosine
);
```
Ensure backward and cross-platform compatibility, handle in-memory `:memory:` databases seamlessly, and write unit tests in `tests/unit/test_vector_ddl.py`.

**Blocked by:** none

**Status:** ready-for-agent

- [ ] Add `sqlite-vec>=0.1.9` to `pyproject.toml` dependencies
- [ ] Load `sqlite_vec.loadable_path()` in `GraphStore._get_conn()`
- [ ] Add `vec_findings` virtual table to `SCHEMA_DDL`
- [ ] Write unit tests in `tests/unit/test_vector_ddl.py` verifying virtual table creation and extension loading
