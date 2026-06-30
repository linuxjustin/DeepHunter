from __future__ import annotations

from typing import Any

from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.rag.chunker import Chunk, TextChunker
from deephunter.rag.semantic_ranker import SemanticRanker


class ContextCompressor:
    """Compress retrieved context by selecting the most relevant chunks.

    Strategies:
      - top_k: keep only top-k chunks by relevance
      - threshold: keep chunks above a relevance threshold
      - max_tokens: keep chunks until token budget is reached
      - extractive: keep only query-relevant sentences
    """

    def __init__(
        self,
        chunker: TextChunker | None = None,
        ranker: SemanticRanker | None = None,
        max_tokens: int = 4096,
        compression_ratio: float = 0.5,
        strategy: str = "max_tokens",
    ) -> None:
        self._chunker = chunker or TextChunker()
        self._ranker = ranker or SemanticRanker()
        self._max_tokens = max_tokens
        self._compression_ratio = compression_ratio
        self._strategy = strategy

    def compress(
        self,
        query: str,
        results: list[tuple[SecurityKnowledgeObject, float]],
    ) -> str:
        if not results:
            return ""

        chunks: list[Chunk] = []
        for sko, _score in results:
            content = sko.raw_content or f"{sko.title} {sko.summary}"
            doc_chunks = self._chunker.chunk(
                content,
                source_id=sko.id,
                metadata={"title": sko.title, "source": sko.source},
            )
            chunks.extend(doc_chunks)

        ranked = self._ranker.rerank_chunks(query, chunks)
        return self._apply_strategy(query, ranked)

    def compress_chunks(
        self,
        query: str,
        chunks: list[Chunk],
    ) -> str:
        if not chunks:
            return ""
        ranked = self._ranker.rerank_chunks(query, chunks)
        return self._apply_strategy(query, ranked)

    def _apply_strategy(self, query: str, ranked: list[tuple[Chunk, float]]) -> str:
        if self._strategy == "top_k":
            k = max(1, int(len(ranked) * self._compression_ratio))
            selected = [c for c, _ in ranked[:k]]

        elif self._strategy == "threshold":
            threshold = 0.5
            selected = [c for c, s in ranked if s >= threshold]
            if not selected:
                selected = [ranked[0][0]]

        elif self._strategy == "extractive":
            selected = self._extractive_compress(query, ranked)

        else:
            selected = self._token_budget_compress(ranked)

        parts: list[str] = []
        for chunk in selected:
            if chunk.metadata.get("title"):
                parts.append(f"[{chunk.metadata['title']}] {chunk.text}")
            else:
                parts.append(chunk.text)

        return "\n\n".join(parts)

    def _token_budget_compress(
        self, ranked: list[tuple[Chunk, float]]
    ) -> list[Chunk]:
        budget = int(self._max_tokens * self._compression_ratio)
        selected: list[Chunk] = []
        used = 0
        for chunk, _score in ranked:
            tokens = chunk.token_count or len(chunk.text.split())
            if used + tokens > budget:
                remaining = budget - used
                if remaining > 10:
                    words = chunk.text.split()[:remaining]
                    chunk.text = " ".join(words)
                    selected.append(chunk)
                break
            selected.append(chunk)
            used += tokens
        return selected

    def _extractive_compress(
        self, query: str, ranked: list[tuple[Chunk, float]]
    ) -> list[Chunk]:
        q_words = set(query.lower().split())
        compressed: list[Chunk] = []
        for chunk, _score in ranked:
            sentences = chunk.text.replace("\n", " ").split(". ")
            kept: list[str] = []
            for sent in sentences:
                sent_words = set(sent.lower().split())
                if q_words & sent_words:
                    kept.append(sent)
            if kept:
                chunk.text = ". ".join(kept)
                compressed.append(chunk)
        return compressed if compressed else [ranked[0][0]]

    @property
    def strategy(self) -> str:
        return self._strategy

    @strategy.setter
    def strategy(self, value: str) -> None:
        valid = {"top_k", "threshold", "max_tokens", "extractive"}
        if value not in valid:
            raise ValueError(f"Invalid strategy: {value}. Valid: {valid}")
        self._strategy = value
