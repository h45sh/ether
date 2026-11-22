# 03: `GraphStore` Vector Indexing & Semantic Search Engine

**What to build:**
Implement vector synchronization and similarity retrieval in `src/ether/graph/store.py`:
- In `upsert_findings_batch()`, compute and upsert 384-d vector embeddings into `vec_findings` (serialized using `sqlite_vec.serialize_float32`).
- Implement `store.semantic_search(session_id: str, query: str, limit: int = 10, min_score: float = 0.0, schema_type: Optional[str] = None) -> List[Dict[str, Any]]`:
  - Embeds query text into vector.
  - Queries `vec_findings` using `WHERE embedding MATCH ? ORDER BY distance LIMIT ?`.
  - Joins with `nodes` table (matching on `session_id` and optional `schema_type` and excluding `stale` nodes by default).
  - Calculates `similarity = 1.0 - distance` and returns rich node dictionaries.
- In `prune_stale_nodes()`, delete corresponding rows from `vec_findings`.
Write unit tests in `tests/unit/test_vector_store.py`.

**Blocked by:** 01: `sqlite-vec` Dependency & Extension Integration in `GraphStore`, 02: Deterministic Offline Vector Embedding Engine & Finding Serialization

**Status:** ready-for-agent

- [ ] Implement `sync_vectors_batch()` and auto-sync in `upsert_findings_batch()`
- [ ] Implement `GraphStore.semantic_search()` with k-NN cosine distance queries
- [ ] Filter out stale nodes and support `schema_type` filtering in vector search
- [ ] Purge `vec_findings` rows on `prune_stale_nodes()` and session deletion
- [ ] Write unit tests in `tests/unit/test_vector_store.py`
