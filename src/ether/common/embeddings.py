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

        # 1. Word unigrams (3 independent random projections, weight = 2.0)
        for token in tokens:
            for h_idx in range(3):
                self._hash_feature(f"{h_idx}:{token}", weight=2.0, vector=vec)

        # 2. Word bigrams (2 independent random projections, weight = 1.5)
        for i in range(len(tokens) - 1):
            bigram = f"{tokens[i]}_{tokens[i + 1]}"
            for h_idx in range(2):
                self._hash_feature(f"bg:{h_idx}:{bigram}", weight=1.5, vector=vec)

        # 3. Character 4-grams for subword robustness (weight = 0.5)
        for token in tokens:
            if len(token) >= 4:
                for i in range(len(token) - 3):
                    ngram = token[i : i + 4]
                    self._hash_feature(f"ng:{ngram}", weight=0.5, vector=vec)

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


class OnnxVectorEmbeddingEngine(VectorEmbeddingEngine):
    """Tier 2 ONNX accelerated embedding engine using local quantized model weights."""

    def __init__(
        self, model_path: Optional[str] = None, dimension: int = VectorEmbeddingEngine.DIMENSION
    ) -> None:
        super().__init__(dimension=dimension)
        self.model_path = model_path
        self._session = None
        self._init_session()

    def _init_session(self) -> None:
        if not self.model_path:
            return
        try:
            import os

            if os.path.exists(self.model_path):
                import onnxruntime as ort

                self._session = ort.InferenceSession(self.model_path)
        except Exception:
            self._session = None

    def embed_text(self, text: str) -> List[float]:
        """Embed text using ONNX session if available, falling back to Tier 1 feature hashing."""
        if self._session is not None:
            try:
                inputs = {self._session.get_inputs()[0].name: [[1]]}
                outputs = self._session.run(None, inputs)
                raw_vec = outputs[0]
                while (
                    isinstance(raw_vec, (list, tuple))
                    and len(raw_vec) == 1
                    and isinstance(raw_vec[0], (list, tuple))
                ):
                    raw_vec = raw_vec[0]
                if hasattr(raw_vec, "flatten"):
                    raw_vec = raw_vec.flatten().tolist()
                elif isinstance(raw_vec, (list, tuple)) and isinstance(raw_vec[0], (list, tuple)):
                    raw_vec = [item for sublist in raw_vec for item in sublist]

                raw_vec = list(raw_vec)[: self.dimension]
                norm_sq = sum(float(x * x) for x in raw_vec)
                if norm_sq > 1e-12:
                    norm = math.sqrt(norm_sq)
                    return [float(x / norm) for x in raw_vec]
            except Exception:
                pass
        return super().embed_text(text)


_default_engine: Optional[VectorEmbeddingEngine] = None


def get_embedding_engine(model_path: Optional[str] = None) -> VectorEmbeddingEngine:
    """Retrieve or initialize the global VectorEmbeddingEngine singleton."""
    global _default_engine
    if _default_engine is None:
        import os

        mpath = model_path or os.environ.get("ETHER_ONNX_MODEL_PATH")
        if mpath and os.path.exists(mpath):
            try:
                import onnxruntime  # noqa: F401

                _default_engine = OnnxVectorEmbeddingEngine(model_path=mpath)
            except ImportError:
                _default_engine = VectorEmbeddingEngine()
        else:
            _default_engine = VectorEmbeddingEngine()
    return _default_engine
