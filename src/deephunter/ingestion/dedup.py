"""Deduplication for the ingestion pipeline.

Provides a pluggable ``DeduplicationStrategy`` interface and a
content-hash implementation.  Future strategies (semantic similarity,
near-duplicate detection) can be added without changing the pipeline.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DedupResult:
    """Result of a deduplication check."""

    is_duplicate: bool
    strategy: str = ""
    existing_id: str | None = None
    similarity: float | None = None


class DeduplicationStrategy(ABC):
    """Interface for deduplication strategies."""

    @abstractmethod
    def is_duplicate(
        self, sko: SecurityKnowledgeObject, store: KnowledgeStore
    ) -> DedupResult:
        """Check if an SKO is a duplicate of one already in the store.

        Args:
            sko: The candidate SKO.
            store: The knowledge store to check against.

        Returns:
            A ``DedupResult`` indicating whether the SKO is a duplicate.
        """


class ContentHashDedup(DeduplicationStrategy):
    """Deduplication based on SHA-256 hash of normalized content.

    Two SKOs are considered duplicates if they have the same
    ``normalized_content`` hash.
    """

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}

    @staticmethod
    def _content_hash(sko: SecurityKnowledgeObject) -> str:
        content = sko.normalized_content or sko.raw_content or ""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _rebuild_cache(self, store: KnowledgeStore) -> None:
        self._cache = {}
        for existing in store.list_all():
            h = self._content_hash(existing)
            self._cache[h] = existing.id

    def is_duplicate(
        self, sko: SecurityKnowledgeObject, store: KnowledgeStore
    ) -> DedupResult:
        candidate_hash = self._content_hash(sko)

        if not self._cache:
            self._rebuild_cache(store)

        existing_id = self._cache.get(candidate_hash)
        if existing_id is not None:
            return DedupResult(
                is_duplicate=True,
                strategy="content_hash",
                existing_id=existing_id,
            )
        self._cache[candidate_hash] = sko.id
        return DedupResult(is_duplicate=False, strategy="content_hash")


class NoOpDedup(DeduplicationStrategy):
    """Deduplication strategy that never flags duplicates.

    Useful when deduplication is disabled.
    """

    def is_duplicate(
        self, sko: SecurityKnowledgeObject, store: KnowledgeStore
    ) -> DedupResult:
        return DedupResult(is_duplicate=False, strategy="noop")


class DeduplicationEngine:
    """Orchestrates one or more deduplication strategies.

    By default, any strategy reporting a duplicate causes the SKO
    to be skipped.  This can be configured via ``require_all``.
    """

    def __init__(
        self,
        strategies: list[DeduplicationStrategy] | None = None,
        require_all: bool = False,
    ) -> None:
        self._strategies = strategies or [NoOpDedup()]
        self._require_all = require_all

    def is_duplicate(
        self, sko: SecurityKnowledgeObject, store: KnowledgeStore
    ) -> DedupResult:
        """Check an SKO against all registered strategies.

        Args:
            sko: The candidate SKO.
            store: The knowledge store.

        Returns:
            The first duplicate result found, or a non-duplicate result.
        """
        if self._require_all:
            all_results = [s.is_duplicate(sko, store) for s in self._strategies]
            if all(r.is_duplicate for r in all_results):
                return all_results[0]
            return DedupResult(is_duplicate=False, strategy="all")
        for strategy in self._strategies:
            result = strategy.is_duplicate(sko, store)
            if result.is_duplicate:
                return result
        return DedupResult(is_duplicate=False, strategy="none")
