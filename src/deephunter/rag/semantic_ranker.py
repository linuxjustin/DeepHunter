from __future__ import annotations

from typing import Any, Callable

from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.rag.chunker import Chunk


class SemanticRanker:
    """Re-rank retrieval results using semantic relevance scoring.

    Supports pluggable scoring functions (cross-encoder, LLM-based,
    or simple heuristic).
    """

    def __init__(
        self,
        scoring_fn: Callable[[str, str], float] | None = None,
    ) -> None:
        self._scoring_fn = scoring_fn or self._default_score

    def rerank(
        self,
        query: str,
        results: list[tuple[SecurityKnowledgeObject, float]],
        top_k: int | None = None,
    ) -> list[tuple[SecurityKnowledgeObject, float]]:
        if not results:
            return results
        scored: list[tuple[SecurityKnowledgeObject, float]] = []
        for sko, original_score in results:
            content = sko.raw_content or f"{sko.title} {sko.summary}"
            relevance = self._scoring_fn(query, content)
            combined = 0.3 * original_score + 0.7 * relevance
            scored.append((sko, combined))
        scored.sort(key=lambda x: x[1], reverse=True)
        if top_k:
            scored = scored[:top_k]
        return scored

    def rerank_chunks(
        self,
        query: str,
        chunks: list[Chunk],
        top_k: int | None = None,
    ) -> list[tuple[Chunk, float]]:
        if not chunks:
            return []
        scored: list[tuple[Chunk, float]] = []
        for chunk in chunks:
            relevance = self._scoring_fn(query, chunk.text)
            scored.append((chunk, relevance))
        scored.sort(key=lambda x: x[1], reverse=True)
        if top_k:
            scored = scored[:top_k]
        return scored

    @staticmethod
    def _default_score(query: str, text: str) -> float:
        q_words = set(query.lower().split())
        t_words = set(text.lower().split())
        if not q_words or not t_words:
            return 0.0
        intersection = q_words & t_words
        return len(intersection) / max(len(q_words), 1)

    @staticmethod
    def token_overlap_score(query: str, text: str) -> float:
        q_tokens = set(query.lower().split())
        t_tokens = set(text.lower().split())
        if not q_tokens or not t_tokens:
            return 0.0
        overlap = q_tokens & t_tokens
        return len(overlap) / max(len(q_tokens), 1)

    @staticmethod
    def keyword_density_score(query: str, text: str) -> float:
        q_words = query.lower().split()
        t_lower = text.lower()
        if not q_words:
            return 0.0
        matches = sum(t_lower.count(w) for w in q_words)
        total_words = len(t_lower.split())
        return matches / max(total_words, 1)
