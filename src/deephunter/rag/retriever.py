"""Retriever — searches SKOs using embedding similarity.

Maintains an in-memory vector index that is built from the
KnowledgeStore's SKOs and supports cosine-similarity search.
"""

from __future__ import annotations

from deephunter.core.config import RAGConfig
from deephunter.core.exceptions import RetrievalError
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.rag.embeddings import EmbeddingProvider, EmbeddingProviderFactory
from deephunter.utils.logging import get_logger

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

logger = get_logger(__name__)


class Retriever:
    """Retrieves relevant SKOs using embedding similarity.

    Builds a vector index from the KnowledgeStore's SKO content,
    then returns the top-k most similar SKOs for a given query.

    Usage::

        store = KnowledgeStore()
        retriever = Retriever(config.rag, store)
        retriever.index()  # Build vector index from all stored SKOs
        results = retriever.query("JWT authentication bypass")
    """

    def __init__(
        self,
        config: RAGConfig,
        store: KnowledgeStore,
        embedding_provider: EmbeddingProvider | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._embedding_provider = embedding_provider or (
            EmbeddingProviderFactory.create(config)
        )
        self._index: dict[str, list[float]] = {}
        self._indexed: bool = False

    def index(self) -> int:
        """Build or rebuild the vector index from all SKOs in the store.

        Returns:
            Number of SKOs indexed.
        """
        if not HAS_NUMPY:
            raise RetrievalError(
                "numpy is required for vector operations. "
                "Install it with: pip install deephunter[rag]"
            )

        skos = self._store.list_all()
        self._index.clear()

        for sko in skos:
            content = sko.raw_content or f"{sko.title} {sko.summary}"
            try:
                vec = self._embedding_provider.embed(content)
                self._index[sko.id] = vec
            except Exception as exc:
                logger.warning("Failed to embed SKO %s: %s", sko.id, exc)

        self._indexed = True
        logger.info("Indexed %d SKOs", len(self._index))
        return len(self._index)

    def query(
        self,
        query: str,
        top_k: int | None = None,
        threshold: float | None = None,
    ) -> list[tuple[SecurityKnowledgeObject, float]]:
        """Retrieve the top-k SKOs most similar to the query.

        Args:
            query: Natural language query string.
            top_k: Number of results to return (default from config).
            threshold: Minimum similarity score (default from config).

        Returns:
            List of (SKO, similarity_score) tuples, sorted by score descending.

        Raises:
            RetrievalError: If the index is empty or not built.
        """
        if not HAS_NUMPY:
            raise RetrievalError("numpy is required for vector operations")
        if not self._index:
            raise RetrievalError(
                "Vector index is empty. Call index() after adding SKOs."
            )

        k = top_k if top_k is not None else self._config.top_k
        t = threshold if threshold is not None else self._config.similarity_threshold

        query_vec = np.array(self._embedding_provider.embed(query))
        query_norm = np.linalg.norm(query_vec)
        if query_norm == 0:
            return []
        query_vec = query_vec / query_norm

        scored: list[tuple[str, float]] = []
        for sko_id, vec in self._index.items():
            sv = np.array(vec)
            sv_norm = np.linalg.norm(sv)
            if sv_norm == 0:
                continue
            similarity = float(np.dot(query_vec, sv / sv_norm))
            scored.append((sko_id, similarity))

        scored.sort(key=lambda x: x[1], reverse=True)
        results: list[tuple[SecurityKnowledgeObject, float]] = []
        for sko_id, score in scored:
            if score < t:
                break
            sko = self._store.get(sko_id)
            if sko is not None:
                results.append((sko, score))
            if len(results) >= k:
                break

        logger.debug("Query returned %d results", len(results))
        return results

    def count_indexed(self) -> int:
        """Return the number of SKOs currently in the index."""
        return len(self._index)

    def clear_index(self) -> None:
        """Clear the vector index."""
        self._index.clear()
        self._indexed = False
