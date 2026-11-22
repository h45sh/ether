"""Deterministic offline vector embedding engine for Ether."""

import hashlib
import math
import re
from typing import List, Optional


class VectorEmbeddingEngine:
    """Generates 384-dimensional normalized float vectors for offline similarity search.

    Uses a deterministic feature-hashing algorithm (token unigrams, bigrams, and character
    trigrams with SHA-256 random projections and L2 normalization). Guarantees zero network
    egress, zero external model downloads, and sub-millisecond execution.
    """

    DIMENSION: int = 384

    def __init__(self, dimension: int = DIMENSION) -> None:
        self.dimension = dimension

    def embed_text(self, text: str) -> List[float]:
        """Convert a text string into a 384-dimensional unit vector."""
        if not text or not text.strip():
            vec = [0.0] * self.dimension
            vec[0] = 1.0
            return vec

        cleaned = text.lower()
        tokens = re.findall(r"\w+", cleaned)
        if not tokens:
            vec = [0.0] * self.dimension
            vec[0] = 1.0
            return vec

        vec = [0.0] * self.dimension

        # 1. Word unigrams (weight = 2.0)
        for token in tokens:
            self._hash_feature(token, weight=2.0, vector=vec)

        # 2. Word bigrams (weight = 1.5)
        for i in range(len(tokens) - 1):
            bigram = f"{tokens[i]}_{tokens[i + 1]}"
            self._hash_feature(bigram, weight=1.5, vector=vec)

        # 3. Character trigrams for subword robustness (weight = 0.5)
        for token in tokens:
            if len(token) >= 3:
                for i in range(len(token) - 2):
                    trigram = token[i : i + 3]
                    self._hash_feature(f"tri:{trigram}", weight=0.5, vector=vec)

        # 4. L2 Normalization to ensure ||v||_2 = 1.0
        norm_sq = sum(x * x for x in vec)
        if norm_sq <= 1e-12:
            vec[0] = 1.0
            return vec

        norm = math.sqrt(norm_sq)
        return [float(x / norm) for x in vec]

    def _hash_feature(self, feature: str, weight: float, vector: List[float]) -> None:
        """Hash feature into dimension bucket with signed projection."""
        digest = hashlib.sha256(feature.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:4], byteorder="big") % self.dimension
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[bucket] += sign * weight

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Batch embedding of text strings."""
        return [self.embed_text(t) for t in texts]

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        """Calculate cosine similarity between two unit vectors: dot(v1, v2)."""
        if len(v1) != len(v2):
            raise ValueError(f"Vector dimensions do not match: {len(v1)} vs {len(v2)}")
        dot = sum(a * b for a, b in zip(v1, v2, strict=True))
        return max(-1.0, min(1.0, dot))


_default_engine: Optional[VectorEmbeddingEngine] = None


def get_embedding_engine() -> VectorEmbeddingEngine:
    """Retrieve or initialize the global VectorEmbeddingEngine singleton."""
    global _default_engine
    if _default_engine is None:
        _default_engine = VectorEmbeddingEngine()
    return _default_engine
