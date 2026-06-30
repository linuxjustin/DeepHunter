from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from deephunter.core.config import RAGConfig
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.rag.bm25_retriever import BM25Retriever
from deephunter.rag.embeddings import EmbeddingProvider, EmbeddingProviderFactory
from deephunter.rag.retriever import Retriever
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class IncrementalIndexer:
    """Supports incremental indexing — only processes SKOs that are new
    or have been updated since the last index build.

    Maintains a checkpoint timestamp to track the last indexing run.
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
        self._last_indexed_at: datetime | None = None
        self._indexed_ids: set[str] = set()
        self._total_indexed: int = 0

    def build_full_index(
        self,
        retriever: Retriever,
        bm25: BM25Retriever | None = None,
    ) -> dict[str, int]:
        skos = self._store.list_all()
        retriever.index()
        if bm25:
            bm25.index_skos(skos)
        self._indexed_ids = {sko.id for sko in skos}
        self._total_indexed = len(skos)
        self._last_indexed_at = datetime.now(timezone.utc)
        logger.info("Full index built: %d SKOs", self._total_indexed)
        return {"indexed": self._total_indexed, "vector": len(skos), "bm25": len(skos) if bm25 else 0}

    def incremental_update(
        self,
        retriever: Retriever,
        bm25: BM25Retriever | None = None,
        new_skos: list[SecurityKnowledgeObject] | None = None,
    ) -> dict[str, int]:
        new_or_updated = new_skos or self._store.list_all()
        if self._last_indexed_at and not new_skos:
            cutoff = self._last_indexed_at
            new_or_updated = [
                sko for sko in new_or_updated
                if sko.id not in self._indexed_ids
                or (sko.metadata or {}).get("updated_at", "")
            ]

        batch_size = self._config.index_update_batch_size
        indexed = 0
        for i in range(0, len(new_or_updated), batch_size):
            batch = new_or_updated[i : i + batch_size]
            for sko in batch:
                if sko.id in self._indexed_ids:
                    self._update_document(retriever, bm25, sko)
                else:
                    self._add_document(retriever, bm25, sko)
                self._indexed_ids.add(sko.id)
            indexed += len(batch)
            logger.debug("Incremental index: %d/%d", indexed, len(new_or_updated))

        self._total_indexed = len(self._indexed_ids)
        self._last_indexed_at = datetime.now(timezone.utc)
        logger.info("Incremental update: %d new/updated SKOs", indexed)
        return {"indexed": indexed, "total": self._total_indexed}

    def _add_document(
        self,
        retriever: Retriever,
        bm25: BM25Retriever | None,
        sko: SecurityKnowledgeObject,
    ) -> None:
        content = sko.raw_content or f"{sko.title} {sko.summary}"
        try:
            vec = self._embedding_provider.embed(content)
            retriever._index[sko.id] = vec
        except Exception as exc:
            logger.warning("Failed to embed SKO %s: %s", sko.id, exc)

        if bm25:
            bm25._corpus[sko.id] = content

    def _update_document(
        self,
        retriever: Retriever,
        bm25: BM25Retriever | None,
        sko: SecurityKnowledgeObject,
    ) -> None:
        self._add_document(retriever, bm25, sko)

    def needs_rebuild(self, force: bool = False) -> bool:
        if force or self._last_indexed_at is None:
            return True
        store_count = len(self._store.list_all())
        return store_count != self._total_indexed

    @property
    def total_indexed(self) -> int:
        return self._total_indexed

    @property
    def last_indexed_at(self) -> datetime | None:
        return self._last_indexed_at

    def clear(self) -> None:
        self._indexed_ids.clear()
        self._total_indexed = 0
        self._last_indexed_at = None
