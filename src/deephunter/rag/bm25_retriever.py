from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.rag.chunker import Chunk, TextChunker


class BM25Retriever:
    """BM25 keyword-based retriever.

    Implements the BM25 ranking function over a corpus of documents.
    Supports indexing SKOs, chunks, or raw text documents.
    """

    def __init__(
        self,
        k1: float = 1.5,
        b: float = 0.75,
        epsilon: float = 0.25,
    ) -> None:
        self._k1 = k1
        self._b = b
        self._epsilon = epsilon
        self._corpus: dict[str, str] = {}
        self._doc_freqs: dict[str, int] = Counter()
        self._doc_lengths: dict[str, int] = {}
        self._avgdl: float = 0.0
        self._num_docs: int = 0
        self._indexed: bool = False

    def index_documents(self, docs: dict[str, str]) -> int:
        """Index a dict of id -> text."""
        self._corpus = dict(docs)
        self._rebuild_stats()
        self._indexed = True
        return len(self._corpus)

    def index_skos(self, skos: list[SecurityKnowledgeObject]) -> int:
        """Index SKOs by their content."""
        docs: dict[str, str] = {}
        for sko in skos:
            content = sko.raw_content or f"{sko.title} {sko.summary}"
            docs[sko.id] = content
        return self.index_documents(docs)

    def index_chunks(self, chunks: list[Chunk]) -> int:
        """Index chunks by chunk index key."""
        docs: dict[str, str] = {}
        for i, c in enumerate(chunks):
            key = f"{c.source_id}:{c.index}" if c.source_id else f"chunk:{i}"
            docs[key] = c.text
        return self.index_documents(docs)

    def _rebuild_stats(self) -> None:
        self._doc_freqs.clear()
        self._doc_lengths.clear()
        total_length = 0

        for doc_id, text in self._corpus.items():
            tokens = self._tokenize(text)
            self._doc_lengths[doc_id] = len(tokens)
            total_length += len(tokens)
            unique = set(tokens)
            for token in unique:
                self._doc_freqs[token] += 1

        self._num_docs = len(self._corpus)
        self._avgdl = total_length / max(self._num_docs, 1)

    def query(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.0,
    ) -> list[tuple[str, float]]:
        if not self._indexed or not self._corpus:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        idf_cache: dict[str, float] = {}
        for token in query_tokens:
            df = self._doc_freqs.get(token, 0)
            idf = math.log(
                1 + (self._num_docs - df + 0.5) / (df + 0.5)
            ) if df > 0 else 0
            idf_cache[token] = max(idf, self._epsilon)

        scored: list[tuple[str, float]] = []
        for doc_id, text in self._corpus.items():
            doc_tokens = self._tokenize(text)
            doc_len = len(doc_tokens)
            if doc_len == 0:
                continue
            doc_counts = Counter(doc_tokens)
            score = 0.0
            for token in query_tokens:
                tf = doc_counts.get(token, 0)
                if tf == 0:
                    continue
                numerator = tf * (self._k1 + 1)
                denominator = tf + self._k1 * (
                    1 - self._b + self._b * doc_len / self._avgdl
                )
                score += idf_cache.get(token, 0) * numerator / denominator
            if score > threshold:
                scored.append((doc_id, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        text = text.lower()
        tokens = re.findall(r"\w+", text)
        return tokens

    def count_indexed(self) -> int:
        return self._num_docs

    def clear(self) -> None:
        self._corpus.clear()
        self._doc_freqs.clear()
        self._doc_lengths.clear()
        self._avgdl = 0.0
        self._num_docs = 0
        self._indexed = False



