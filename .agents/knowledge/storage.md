# Domain Knowledge: Storage & Graph Persistence (Tier 2)

## 1. Persistence Seams & Facades
- **Unified Graph Store**: Graph database interactions are encapsulated inside `GraphStore` (`src/ether/graph/store.py`), backed by `WriteQueueWorker` for serialized writes and `VectorIndex` for vector search.
- **Async Execution & Concurrency**: Never run synchronous, blocking SQLite calls directly on the event loop. Concurrent writes are batched and committed by `WriteQueueWorker` in adaptive 25ms windows. Reads use a dedicated read connection pool with `PRAGMA query_only = ON`.
- **WAL Journaling**: SQLite connections use write-ahead logging (`PRAGMA journal_mode=WAL;`), synchronous normal mode, and foreign keys enabled on every connection.
- **Forensic Audit Manifests**: Every executed action appends an `AuditRecord` to `~/.ether/audit/{session_id}.jsonl` with SHA-256 cryptographic hash chaining and automatic session-close gzip compaction.

## 2. Ingestion Performance & Atomic Micro-Batching
- **Batch Insertion Mandate**: Executing individual `INSERT` statements inside loops is strictly prohibited ($O(N)$ transaction overhead). Bulk imports must use `db.executemany()` or `upsert_findings_batch()`.
- **Throughput Contract**: GraphStore ingestion must maintain $\ge 2,000\text{ entities/sec}$ (hard floor $\ge 1,200\text{ entities/sec}$ under shared virtualized CI).
- **Bulk Query Scale Limits**: 5,000 nodes and 2,500 edges must be queried in $\le 500\text{ms}$ in SQLite via parameter-bound queries and indexed foreign keys.

## 3. Vector Memory & Finding RAG (`sqlite-vec`)
- **Embedded Offline Vector Memory**: Discovered services, technologies, endpoints, and vulnerabilities are automatically mapped to 384-dimensional unit vectors ($||v||_2 = 1.0$) using `VectorEmbeddingEngine` and indexed in `vec_findings USING vec0`.
- **Sub-millisecond Retrieval**: Natural language queries search via k-NN cosine distance without network egress or remote API calls.
- **Lifecycle Cleanup**: Vector embeddings are atomically synchronized on finding upsert and purged when stale nodes or sessions are deleted.

## 4. Temporal State Decay & Invariant Identity Anchoring
- **State Confidence Windows**: Nodes transition from `confirmed` to `flapping` or `stale` based on TTL windows.
- **Cross-IP Identity Migration**: Ephemeral IP changes are resolved by anchoring Primary Identity Keys to invariant cryptographic fingerprints (`tls:<sha256>`, `ssh:<fingerprint>`, `favicon:<hash>`).
