# Specification: Epoch 2 Milestone 2.4 — Embedded Offline Vector Memory & Finding RAG (`sqlite-vec`)

## 1. Objective & Scope

Milestone 2.4 equips Ether with native offline vector memory and semantic finding retrieval (RAG) by integrating `sqlite-vec` directly into `GraphStore`. This allows autonomous AI agents and cybersecurity operators to perform semantic similarity queries over attack surfaces (e.g. "outdated SSL endpoints", "remote code execution vulnerabilities", "exposed redis databases") using natural language intent, executing 100% offline with zero external network egress or API keys.

---

## 2. Architecture & Design Principles

### 2.1 In-Process Vector Virtual Table (`sqlite-vec`)
- `GraphStore` enables extension loading upon establishing database connections:
  ```python
  await conn.enable_load_extension(True)
  await conn.load_extension(sqlite_vec.loadable_path())
  await conn.enable_load_extension(False)
  ```
- A dedicated virtual table `vec_findings` indexes 384-dimensional cosine distance embeddings directly tied to finding `node_id`:
  ```sql
  CREATE VIRTUAL TABLE IF NOT EXISTS vec_findings USING vec0(
      node_id text primary key,
      embedding float[384] distance_metric=cosine
  );
  ```
- **Single-File Forensic Portability:** All embeddings live inside the session database; database backups, exports (`ether graph export`), and forensic copies retain all vector indices automatically.

### 2.2 Deterministic Offline Embedding Engine (`VectorEmbeddingEngine`)
- Invariant: Zero external network egress, zero model download delays during runtime or CI test execution.
- Generates 384-dimensional normalized float vectors ($||v||_2 = 1.0$) via subword and token feature hashing with SHA-256 seeding.
- Computes cosine similarity accurately for natural language domain concepts (keywords, CVE identifiers, ports, technologies, severity markers).
- Pluggable design supports local quantized ONNX models (`fastembed` / `onnxruntime-cpu`) when pre-downloaded weights are present.

### 2.3 Declarative Finding Semantic Serialization (`to_semantic_text()`)
- `BaseFinding` provides a default template:
  `"{schema_type}: " + ", ".join(f"{k}={v}" for k, v in pik.items()) + ". Data: " + ", ".join(f"{k}={v}" for k, v in data.items())`
- Core schema subclasses provide tailored high-semantic density templates:
  - `NetworkHost`: `"Discovered Host IP: {ip}. Hostname: {hostname}. OS: {os}."`
  - `NetworkService`: `"{service_name} service on {host_ip}:{port}/{protocol}. Product banner: {banner}. TLS: {tls_cert_sha256}."`
  - `WebEndpoint`: `"Web Endpoint at {url}. Status HTTP {status_code}. Page Title: '{title}'. Server header: {server}."`
  - `WebTechnology`: `"Detected Technology: {technology_name} version {version} on {url}. Categories: {categories}."`
  - `VulnerabilityFound`: `"Vulnerability {vuln_id} ({title}) on {host_ip}:{port}. Severity: {severity}. Description: {description}."`
  - `CredentialDiscovered`: `"Discovered Credential for {username} ({account_type}) on {host_ip}. Source: {source}."`
  - `DnsRecord`: `"DNS {record_type} Record for {domain} resolving to {value}. TTL: {ttl_seconds}."`

### 2.4 Asynchronous Batch Vector Ingestion
- `upsert_findings_batch()` completes without blocking streaming process logs.
- Reactive `on_findings_batch` hook or immediate batch vector synchronization generates embeddings and upserts into `vec_findings`:
  ```sql
  INSERT INTO vec_findings(node_id, embedding)
  VALUES (?, ?)
  ON CONFLICT(node_id) DO UPDATE SET embedding = excluded.embedding;
  ```
- `prune_stale_nodes()` automatically purges orphaned embeddings from `vec_findings`.

### 2.5 Query Surfaces: SDK, MCP, and CLI
1. **SDK API:**
   `store.semantic_search(session_id, query, limit=10, min_score=0.0, schema_type=None)`
   Returns node dictionaries joined with `distance` and calculated `similarity = 1.0 - distance`.
2. **Agent Telemetry RAG (`GraphTelemetryCompiler`):**
   `compile_telemetry_snapshot(objective="...")` retrieves top-k semantically relevant findings matching the agent's current task objective and injects them into `rag_findings`.
3. **MCP Tool:**
   `search_findings_semantic(query: str, limit: int = 10, schema_type: Optional[str] = None)`
4. **CLI Command:**
   `ether graph search <session_id> "<query>" [--limit 10] [--min-score 0.5] [--json]`

---

## 3. SQLite DDL Extensions

```sql
CREATE VIRTUAL TABLE IF NOT EXISTS vec_findings USING vec0(
    node_id text primary key,
    embedding float[384] distance_metric=cosine
);
```

---

## 4. Test Strategy

1. **Unit Tests (`tests/unit/test_vector_engine.py`):**
   - Verify 384-dimensional unit vector generation, L2 norm invariance ($||v||_2 = 1.0 \pm 10^{-5}$).
   - Verify semantic clustering: "remote code execution" has higher similarity to "CVE-2024-9999 RCE" than to "8.8.8.8 DNS resolver".
2. **Integration Tests (`tests/unit/test_vector_store.py`):**
   - Verify `vec_findings` creation, insert, and vector k-NN search via `sqlite-vec`.
   - Verify asynchronous batch indexing on `upsert_findings_batch()`.
   - Verify cascading deletion when nodes are pruned.
3. **Telemetry & MCP Tests (`tests/unit/test_vector_rag.py`):**
   - Verify `compile_telemetry_snapshot(objective=...)` injects relevant RAG findings.
   - Verify MCP tool `search_findings_semantic`.
   - Verify CLI `ether graph search`.
