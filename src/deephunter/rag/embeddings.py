"""Embedding provider abstraction.

Defines a pluggable interface for generating text embeddings,
with a default implementation using numpy-based document vectors
for offline operation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from deephunter.core.config import RAGConfig
from deephunter.core.exceptions import RetrievalError
from deephunter.utils.logging import get_logger

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

logger = get_logger(__name__)


class EmbeddingProvider(ABC):
    """Abstract interface for embedding generation.

    Implementations can wrap local models, API services (OpenAI,
    Hugging Face, etc.), or use simple fallback mechanisms.
    """

    @abstractmethod
    def embed(self, text: str) -> List[float]:
        """Generate an embedding vector for a single text string.

        Args:
            text: The input text.

        Returns:
            A list of floats representing the embedding vector.
        """

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for a batch of texts.

        The default implementation calls ``embed`` sequentially.
        Subclasses may override for batched API calls.
        """
        return [self.embed(t) for t in texts]

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Return the dimensionality of the embedding vectors."""


class RandomEmbeddingProvider(EmbeddingProvider):
    """Fallback provider that generates deterministic random embeddings.

    This is useful for development, testing, or offline operation
    where no embedding model is available.  The seed is derived from
    the text hash, so the same text always produces the same vector.

    Not suitable for production retrieval — use a real embedding model.
    """

    def __init__(self, dimension: int = 384) -> None:
        if not HAS_NUMPY:
            raise RetrievalError(
                "numpy is required for RandomEmbeddingProvider. "
                "Install it with: pip install deephunter[rag]"
            )
        self._dimension = dimension

    def embed(self, text: str) -> List[float]:
        seed = hash(text) & 0xFFFFFFFF
        rng = np.random.default_rng(seed)
        vec = rng.random(self._dimension).astype(np.float64)
        vec = vec / (np.linalg.norm(vec) + 1e-10)
        return vec.tolist()

    @property
    def dimension(self) -> int:
        return self._dimension


class EmbeddingProviderFactory:
    """Creates embedding providers from configuration."""

    @staticmethod
    def create(config: RAGConfig) -> EmbeddingProvider:
        """Create an embedding provider based on config.

        Args:
            config: RAG configuration.

        Returns:
            An EmbeddingProvider instance.

        Raises:
            RetrievalError: If the configured model is unsupported.
        """
        model = config.embedding_model.lower()
        if model == "random":
            return RandomEmbeddingProvider()
        if model.startswith("text-embedding"):
            logger.warning(
                "Remote embedding model '%s' is not available in offline mode. "
                "Falling back to RandomEmbeddingProvider.",
                model,
            )
            return RandomEmbeddingProvider()
        msg = f"Unsupported embedding model: {config.embedding_model}"
        raise RetrievalError(msg)