from __future__ import annotations

from typing import Any

from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.rag.bm25_retriever import BM25Retriever
from deephunter.rag.retriever import Retriever


class HybridRetriever:
    """Combines BM25 keyword scores and vector similarity scores.

    Normalizes both score ranges to [0,1] and combines using
    configurable weights.  Only documents present in both result
    sets (or the union) are returned.
    """

    def __init__(
        self,
        vector_retriever: Retriever,
        bm25_retriever: BM25Retriever,
        store: KnowledgeStore,
        bm25_weight: float = 0.5,
        vector_weight: float = 0.5,
    ) -> None:
        self._vector = vector_retriever
        self._bm25 = bm25_retriever
        self._store = store
        self._bm25_weight = bm25_weight
        self._vector_weight = vector_weight

    def index_vector(self) -> int:
        return self._vector.index()

    def index_bm25(self, skos: list[SecurityKnowledgeObject]) -> int:
        return self._bm25.index_skos(skos)

    def query(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.0,
    ) -> list[tuple[SecurityKnowledgeObject, float]]:
        bm25_results = self._bm25.query(query, top_k=max(top_k * 3, 20), threshold=0.0)
        try:
            vector_results = self._vector.query(query, top_k=max(top_k * 3, 20), threshold=0.0)
        except Exception:
            vector_results = []

        bm25_scores = self._normalize({doc_id: score for doc_id, score in bm25_results})
        vector_scores = self._normalize({sko.id: score for sko, score in vector_results})

        all_ids = set(bm25_scores.keys()) | set(vector_scores.keys())
        merged: list[tuple[str, float]] = []
        for doc_id in all_ids:
            b_score = bm25_scores.get(doc_id, 0.0)
            v_score = vector_scores.get(doc_id, 0.0)
            combined = self._bm25_weight * b_score + self._vector_weight * v_score
            if combined > threshold:
                merged.append((doc_id, combined))

        merged.sort(key=lambda x: x[1], reverse=True)
        merged = merged[:top_k]

        results: list[tuple[SecurityKnowledgeObject, float]] = []
        for doc_id, score in merged:
            sko = self._store.get(doc_id)
            if sko is not None:
                results.append((sko, score))
        return results

    @staticmethod
    def _normalize(scores: dict[str, float]) -> dict[str, float]:
        if not scores:
            return scores
        max_score = max(scores.values())
        if max_score == 0:
            return scores
        return {k: v / max_score for k, v in scores.items()}

    def clear(self) -> None:
        self._bm25.clear()
        self._vector.clear_index()
