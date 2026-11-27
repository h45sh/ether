"""Unit tests for two-tier hermetic semantic vector embeddings in Ether."""

import math
from unittest.mock import MagicMock

import pytest

from ether.common.embeddings import (
    OnnxVectorEmbeddingEngine,
    VectorEmbeddingEngine,
    get_embedding_engine,
)


@pytest.mark.fast
def test_vector_engine_tier1_determinism_and_norm():
    """Verify Tier 1 feature hasher produces deterministic 384-dim unit vectors."""
    engine = VectorEmbeddingEngine(dimension=384)

    text = "Apache 2.4.49 path traversal and remote code execution vulnerability"
    vec1 = engine.embed_text(text)
    vec2 = engine.embed_text(text)

    # Dimension check
    assert len(vec1) == 384
    assert len(vec2) == 384

    # Determinism check
    assert vec1 == vec2

    # L2 Unit Norm check: sum(x^2) == 1.0
    l2_norm = math.sqrt(sum(x * x for x in vec1))
    assert abs(l2_norm - 1.0) < 1e-5


@pytest.mark.fast
def test_vector_engine_tier1_cosine_similarity():
    """Verify cosine similarity correctly identifies related vs unrelated security findings."""
    engine = VectorEmbeddingEngine()

    query = "OpenSSH remote root exploit"
    related = "OpenSSH 7.2p1 privilege escalation vulnerabilities"
    unrelated = "WordPress contact form plugin arbitrary file upload"

    v_query = engine.embed_text(query)
    v_related = engine.embed_text(related)
    v_unrelated = engine.embed_text(unrelated)

    sim_related = engine.cosine_similarity(v_query, v_related)
    sim_unrelated = engine.cosine_similarity(v_query, v_unrelated)

    # Related should have higher similarity than completely unrelated
    assert sim_related > sim_unrelated
    assert -1.0 <= sim_related <= 1.0
    assert -1.0 <= sim_unrelated <= 1.0


@pytest.mark.fast
def test_onnx_tier2_graceful_fallback():
    """Verify Tier 2 engine gracefully falls back to Tier 1 when ONNX weights are not present."""
    engine = OnnxVectorEmbeddingEngine(model_path="/nonexistent/model.onnx")
    vec = engine.embed_text("nmap port scan 443 open")

    assert len(vec) == 384
    l2_norm = math.sqrt(sum(x * x for x in vec))
    assert abs(l2_norm - 1.0) < 1e-5


@pytest.mark.fast
def test_onnx_tier2_active_promotion():
    """Verify Tier 2 engine utilizes ONNX session when available."""
    mock_session = MagicMock()
    # Mock ONNX run output: shape (1, 384)
    mock_output = [[1.0] * 384]
    mock_session.run.return_value = [mock_output]

    engine = OnnxVectorEmbeddingEngine(model_path=None)
    engine._session = mock_session

    vec = engine.embed_text("testing onnx execution")
    assert len(vec) == 384
    l2_norm = math.sqrt(sum(x * x for x in vec))
    assert abs(l2_norm - 1.0) < 1e-5


@pytest.mark.fast
def test_get_embedding_engine_singleton():
    """Verify get_embedding_engine returns initialized singleton."""
    engine = get_embedding_engine()
    assert isinstance(engine, VectorEmbeddingEngine)
