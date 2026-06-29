"""Tests for the RAG engine."""

from __future__ import annotations

import pytest

from deephunter.core.config import RAGConfig
from deephunter.core.exceptions import RetrievalError
from deephunter.rag.embeddings import (
    EmbeddingProviderFactory,
    RandomEmbeddingProvider,
)
from deephunter.rag.retriever import Retriever


class TestRandomEmbeddingProvider:
    def test_embed(self) -> None:
        provider = RandomEmbeddingProvider(dimension=384)
        vec = provider.embed("test text")
        assert len(vec) == 384
        assert all(isinstance(v, float) for v in vec)

    def test_deterministic(self) -> None:
        provider = RandomEmbeddingProvider(dimension=384)
        vec1 = provider.embed("hello world")
        vec2 = provider.embed("hello world")
        assert vec1 == vec2

    def test_different_inputs(self) -> None:
        provider = RandomEmbeddingProvider(dimension=384)
        vec1 = provider.embed("hello")
        vec2 = provider.embed("world")
        assert vec1 != vec2

    def test_embed_batch(self) -> None:
        provider = RandomEmbeddingProvider(dimension=128)
        texts = ["a", "b", "c"]
        vectors = provider.embed_batch(texts)
        assert len(vectors) == 3
        assert all(len(v) == 128 for v in vectors)

    def test_dimension(self) -> None:
        provider = RandomEmbeddingProvider(dimension=768)
        assert provider.dimension == 768

    def test_unit_vector(self) -> None:
        provider = RandomEmbeddingProvider(dimension=10)
        vec = provider.embed("test")
        import math
        norm = math.sqrt(sum(v * v for v in vec))
        assert abs(norm - 1.0) < 1e-9


class TestEmbeddingProviderFactory:
    def test_random_provider(self) -> None:
        config = RAGConfig(embedding_model="random")
        provider = EmbeddingProviderFactory.create(config)
        assert isinstance(provider, RandomEmbeddingProvider)

    def test_fallback_from_remote(self) -> None:
        config = RAGConfig(embedding_model="text-embedding-3-small")
        provider = EmbeddingProviderFactory.create(config)
        assert isinstance(provider, RandomEmbeddingProvider)

    def test_unsupported_model(self) -> None:
        config = RAGConfig(embedding_model="nonexistent-model")
        with pytest.raises(RetrievalError):
            EmbeddingProviderFactory.create(config)


class TestRetriever:
    def test_init(self, sample_config, empty_store) -> None:
        retriever = Retriever(sample_config.rag, empty_store)
        assert retriever.count_indexed() == 0
        assert retriever._indexed is False

    def test_index_empty(self, sample_config, empty_store) -> None:
        retriever = Retriever(sample_config.rag, empty_store)
        count = retriever.index()
        assert count == 0

    def test_index_and_query(self, sample_config, populated_store) -> None:
        retriever = Retriever(sample_config.rag, populated_store)
        count = retriever.index()
        assert count == 3

        results = retriever.query("authentication bypass")
        assert isinstance(results, list)

    def test_query_empty_index(self, sample_config, empty_store) -> None:
        retriever = Retriever(sample_config.rag, empty_store)
        with pytest.raises(RetrievalError, match="empty"):
            retriever.query("test")

    def test_clear_index(self, sample_config, populated_store) -> None:
        retriever = Retriever(sample_config.rag, populated_store)
        retriever.index()
        assert retriever.count_indexed() == 3
        retriever.clear_index()
        assert retriever.count_indexed() == 0
