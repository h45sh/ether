# ADR 0007: Embedded Offline Vector Memory & Finding RAG (`sqlite-vec`)

## Status
Accepted

## Context
In Epoch 1 and Epoch 2 (Milestones 2.1–2.3), Ether established a deterministic graph model, token-budgeted dynamic knapsack compiler, zero-token semantic graph diff engine, and temporal state decay with cryptographic identity anchoring.
However, autonomous AI agents and cybersecurity operators face a semantic discovery barrier:
1. **Keyword-Only Matching Fails on Attack Surface Nuance:** Exact PIK and relational edge queries cannot find "potential remote code execution flaws" or "web servers with outdated TLS configurations" unless the agent already knows exact port numbers or vulnerability IDs.
2. **Context Window Saturation on Large Surface Reconnaissance:** In scans yielding hundreds of services and endpoints, passing all raw findings into LLM context wastes tokens and increases hallucinations.
3. **Airgapped / Strict Zero-Egress Invariant:** Cloud vector databases (Pinecone, Qdrant Cloud) or remote embedding APIs (OpenAI `text-embedding-3`, Cohere) violate Ether's strict airgapped headless invariant. All vector memory and retrieval must execute 100% offline with zero external network egress.

## Decision
1. **Embedded SQLite Vector Table (`sqlite-vec`):**
   - Direct integration of `sqlite-vec` (`vec0` virtual table engine) loaded into `GraphStore` via `aiosqlite` extension loading (`sqlite_vec.loadable_path()`).
   - Define a dedicated virtual table:
     ```sql
     CREATE VIRTUAL TABLE IF NOT EXISTS vec_findings USING vec0(
         node_id text primary key,
         embedding float[384] distance_metric=cosine
     );
     ```
   - Embeddings are tied directly to primary finding `node_id`s, preserving single-file SQLite database portability, atomic transactions, and automated forensic archiving (`ether graph export`).

2. **Deterministic Offline Vector Embedding Engine (`VectorEmbeddingEngine`):**
   - Provide a zero-network, local vectorization engine generating 384-dimensional unit float vectors.
   - Implement feature-hashed subword/token hashing with L2 normalization as the robust, hermetic baseline (zero weight downloads, <0.05ms latency, airgap-safe).
   - Support pluggable ONNX-quantized local embedding models (`fastembed`) when local weights are pre-provisioned.

3. **Declarative Finding Semantic Text Representation (`to_semantic_text()`):**
   - Standardize human-readable text representations on `BaseFinding` and subclasses (`vulnerability.found`, `network.service`, `web.technology`, `web.endpoint`, `credential.discovered`) to maximize semantic retrieval quality without JSON syntax noise.

4. **Asynchronous Vector Ingestion & Real-Time Sync:**
   - Ingest finding vectors without degrading high-throughput network stream ingestion (<10ms).
   - Hook into `GraphStore.on_findings_batch()` to asynchronously compute and upsert vectors into `vec_findings`.
   - Purge vectors automatically when nodes are pruned via `GraphStore.prune_stale_nodes()`.

5. **Three-Tier Semantic RAG Retrieval Interface:**
   - **Store API**: `store.semantic_search(session_id, query, limit=10, threshold=0.7)` returning node records with similarity distance scores.
   - **Agent Telemetry RAG**: `GraphTelemetryCompiler.compile_telemetry_snapshot(objective=...)` injecting top-k semantically relevant findings for agent goal directedness.
   - **MCP Tool**: `search_findings_semantic(query, limit, schema_type)` for natural language vector queries by connected agents.
   - **CLI**: `ether graph search <session_id> "<query>"`.

## Consequences
- Enables autonomous agents to query attack surfaces using natural language intent ("unauthenticated endpoints", "critical CVEs", "database services").
- Preserves 100% offline invariant with zero third-party API dependencies or network egress.
- Retains unified single-file SQLite architecture without separate external vector store processes.
- Maintains sub-100ms CLI search latency and sub-10ms finding ingestion throughput.
