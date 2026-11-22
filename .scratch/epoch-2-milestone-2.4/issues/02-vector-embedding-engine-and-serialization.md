# 02: Deterministic Offline Vector Embedding Engine & Finding Serialization

**What to build:**
Create `src/ether/common/embeddings.py` implementing `VectorEmbeddingEngine`:
- Generates 384-dimensional normalized float vectors ($||v||_2 = 1.0$) using deterministic subword/token feature hashing with SHA-256 seeding.
- Zero network egress, zero runtime weight downloads, <0.1ms latency per text.
- Provides `embed_text(text: str) -> List[float]` and `embed_batch(texts: List[str]) -> List[List[float]]`.
Implement `.to_semantic_text()` on `BaseFinding` in `src/ether/schemas/base.py` with custom high-density semantic text implementations in `NetworkHost`, `NetworkService`, `WebEndpoint`, `WebTechnology`, `VulnerabilityFound`, `CredentialDiscovered`, and `DnsRecord`. Write unit tests in `tests/unit/test_vector_engine.py` verifying vector dimensionality, unit norm invariance, and semantic clustering.

**Blocked by:** none

**Status:** completed

- [x] Implement `VectorEmbeddingEngine` in `src/ether/common/embeddings.py`
- [x] Implement `.to_semantic_text()` on `BaseFinding` and core finding schemas
- [x] Verify 384-dimensional float vector output and $||v||_2 = 1.0$ unit normalization
- [x] Write unit tests in `tests/unit/test_vector_engine.py` verifying vector clustering and semantic text templates
