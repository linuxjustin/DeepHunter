"""Tests for Sprint C RAG Engine components."""
from __future__ import annotations

import pytest

from deephunter.core.config import RAGConfig
from deephunter.core.types import Metadata as SKOMetadata
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.rag.bm25_retriever import BM25Retriever
from deephunter.rag.chunker import Chunk, TextChunker
from deephunter.rag.citation_tracker import CitationTracker
from deephunter.rag.context_compressor import ContextCompressor
from deephunter.rag.incremental_index import IncrementalIndexer
from deephunter.rag.metadata_filter import MetadataFilter
from deephunter.rag.semantic_ranker import SemanticRanker


@pytest.fixture
def sample_skos() -> list[SecurityKnowledgeObject]:
    return [
        SecurityKnowledgeObject(
            id="sko-a1b2c3d4e5f6",
            title="JWT Authentication Bypass",
            summary="Techniques for bypassing JWT authentication",
            raw_content="JWT tokens use a header.payload.signature format. Common attacks include algorithm confusion (none, HS256 vs RS256), weak secret cracking, and expired token reuse.",
            source="https://example.com/jwt",
            tags=["jwt", "authentication", "bypass"],
        ),
        SecurityKnowledgeObject(
            id="sko-b2c3d4e5f6a7",
            title="SQL Injection Prevention",
            summary="How to prevent SQL injection in web applications",
            raw_content="SQL injection occurs when untrusted data is interpolated into SQL queries. Parameterized queries and prepared statements are the primary defense.",
            source="https://example.com/sqli",
            tags=["sql", "injection", "prevention"],
        ),
        SecurityKnowledgeObject(
            id="sko-c3d4e5f6a7b8",
            title="XSS Attack Vectors",
            summary="Cross-site scripting attack types and detection",
            raw_content="Cross-site scripting (XSS) enables attackers to inject malicious scripts into web pages. Three main types: Reflected, Stored, DOM-based.",
            source="https://example.com/xss",
            tags=["xss", "scripting", "injection"],
        ),
        SecurityKnowledgeObject(
            id="sko-d4e5f6a7b8c9",
            title="Server-Side Request Forgery",
            summary="SSRF attacks and mitigation strategies",
            raw_content="Server-Side Request Forgery (SSRF) allows attackers to make requests from the server to internal resources.",
            source="https://example.com/ssrf",
            tags=["ssrf", "server-side", "request forgery"],
        ),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# TextChunker
# ═══════════════════════════════════════════════════════════════════════════════


class TestTextChunker:
    def test_chunk_empty(self) -> None:
        c = TextChunker(chunk_size=10, by_tokens=False)
        assert c.chunk("") == []

    def test_chunk_small_text_by_chars(self) -> None:
        c = TextChunker(chunk_size=100, by_tokens=False)
        chunks = c.chunk("Hello world", source_id="src1")
        assert len(chunks) == 1
        assert chunks[0].text == "Hello world"
        assert chunks[0].source_id == "src1"

    def test_chunk_by_tokens(self) -> None:
        c = TextChunker(chunk_size=3, chunk_overlap=0, by_tokens=True)
        text = "one two three four five six"
        chunks = c.chunk(text)
        assert len(chunks) >= 2

    def test_chunk_with_metadata(self) -> None:
        c = TextChunker(chunk_size=100, by_tokens=False)
        chunks = c.chunk("test content", source_id="src2", metadata={"key": "val"})
        assert len(chunks) == 1
        assert chunks[0].metadata.get("key") == "val"

    def test_chunk_document_with_sections(self) -> None:
        c = TextChunker(chunk_size=100, by_tokens=False)
        text = "# Intro\nHello\n# Details\nWorld"
        chunks = c.chunk_document(text, section_pattern=r"# \w+")
        assert len(chunks) >= 2

    def test_token_count(self) -> None:
        c = TextChunker()
        count = c._estimate_tokens("one two three")
        assert count == 3

    def test_properties(self) -> None:
        c = TextChunker(chunk_size=100, chunk_overlap=20)
        assert c.chunk_size == 100
        assert c.chunk_overlap == 20


# ═══════════════════════════════════════════════════════════════════════════════
# BM25Retriever
# ═══════════════════════════════════════════════════════════════════════════════


class TestBM25Retriever:
    def test_empty(self) -> None:
        bm25 = BM25Retriever()
        assert bm25.query("test") == []

    def test_index_and_query(self) -> None:
        bm25 = BM25Retriever()
        docs = {
            "doc1": "JWT authentication bypass using algorithm none attack",
            "doc2": "SQL injection prevention with parameterized queries",
            "doc3": "XSS cross site scripting reflected stored DOM",
        }
        count = bm25.index_documents(docs)
        assert count == 3
        results = bm25.query("JWT authentication")
        assert len(results) > 0
        assert results[0][0] == "doc1"
        assert results[0][1] > 0

    def test_relevance_ordering(self) -> None:
        bm25 = BM25Retriever()
        docs = {
            "d1": "authentication bypass jwt tokens security",
            "d2": "unrelated content about cooking recipes food",
        }
        bm25.index_documents(docs)
        results = bm25.query("authentication jwt")
        assert len(results) >= 1
        assert results[0][0] == "d1"

    def test_query_empty_string(self) -> None:
        bm25 = BM25Retriever()
        bm25.index_documents({"doc1": "some content"})
        assert bm25.query("") == []

    def test_index_skos(self, sample_skos) -> None:
        bm25 = BM25Retriever()
        count = bm25.index_skos(sample_skos)
        assert count == 4
        results = bm25.query("JWT bypass")
        assert len(results) > 0

    def test_clear(self) -> None:
        bm25 = BM25Retriever()
        bm25.index_documents({"doc1": "test"})
        assert bm25.count_indexed() == 1
        bm25.clear()
        assert bm25.count_indexed() == 0

    def test_rebuild_replaces(self) -> None:
        bm25 = BM25Retriever()
        bm25.index_documents({"doc1": "first", "doc2": "second"})
        assert bm25.count_indexed() == 2
        bm25.index_documents({"doc3": "third"})
        assert bm25.count_indexed() == 1


# ═══════════════════════════════════════════════════════════════════════════════
# MetadataFilter
# ═══════════════════════════════════════════════════════════════════════════════


class TestMetadataFilter:
    def test_eq_filter(self) -> None:
        items = [(self._make_sko("a", [SKOMetadata(key="category", value="injection")]), 1.0)]
        f = MetadataFilter()
        result = f.filter(items, {"category": "injection"})
        assert len(result) == 1

    def test_no_match(self) -> None:
        items = [(self._make_sko("a", [SKOMetadata(key="category", value="auth")]), 1.0)]
        f = MetadataFilter()
        result = f.filter(items, {"category": "injection"})
        assert len(result) == 0

    def test_empty_filters(self) -> None:
        items = [(self._make_sko("a", []), 1.0)]
        f = MetadataFilter()
        assert len(f.filter(items, {})) == 1
        assert len(f.filter(items, [])) == 1

    def test_exists_filter(self) -> None:
        items = [(self._make_sko("a", [SKOMetadata(key="category", value="x")]), 1.0)]
        f = MetadataFilter()
        result = f.filter(items, [{"field": "category", "op": "exists", "value": True}])
        assert len(result) == 1

    @staticmethod
    def _make_sko(tag: str, meta: list) -> SecurityKnowledgeObject:
        return SecurityKnowledgeObject(
            id=f"sko-{tag}{'0' * (12 - len(tag))}",
            title="Test",
            summary="",
            source="https://example.com/t",
            metadata=meta,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SemanticRanker
# ═══════════════════════════════════════════════════════════════════════════════


class TestSemanticRanker:
    def test_default_scoring(self) -> None:
        ranker = SemanticRanker()
        score = ranker._default_score("authentication bypass", "JWT authentication bypass techniques")
        assert score > 0

    def test_no_overlap(self) -> None:
        ranker = SemanticRanker()
        score = ranker._default_score("python", "cooking recipes")
        assert score == 0.0

    def test_rerank(self, sample_skos) -> None:
        ranker = SemanticRanker()
        results = [(s, 0.5) for s in sample_skos]
        reranked = ranker.rerank("authentication JWT bypass", results, top_k=2)
        assert len(reranked) == 2
        assert reranked[0][0].id == "sko-a1b2c3d4e5f6"

    def test_rerank_chunks(self) -> None:
        ranker = SemanticRanker()
        chunks = [
            Chunk(text="authentication bypass techniques", index=0),
            Chunk(text="cooking recipes food", index=1),
            Chunk(text="JWT token security", index=2),
        ]
        reranked = ranker.rerank_chunks("authentication JWT", chunks, top_k=2)
        assert len(reranked) == 2

    def test_empty_results(self) -> None:
        ranker = SemanticRanker()
        assert ranker.rerank("test", []) == []
        assert ranker.rerank_chunks("test", []) == []

    def test_token_overlap_score(self) -> None:
        score = SemanticRanker.token_overlap_score("auth bypass", "authentication bypass methods")
        assert score > 0

    def test_keyword_density_score(self) -> None:
        score = SemanticRanker.keyword_density_score("jwt", "JWT JWT JWT token security")
        assert score > 0.5


# ═══════════════════════════════════════════════════════════════════════════════
# ContextCompressor
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextCompressor:
    def test_empty_results(self) -> None:
        cc = ContextCompressor()
        assert cc.compress("test", []) == ""

    def test_compress_top_k(self, sample_skos) -> None:
        cc = ContextCompressor(strategy="top_k", compression_ratio=0.5)
        results = [(s, 1.0) for s in sample_skos]
        compressed = cc.compress("authentication", results)
        assert "JWT" in compressed or "authentication" in compressed.lower()

    def test_compress_threshold(self, sample_skos) -> None:
        cc = ContextCompressor(strategy="threshold")
        results = [(sample_skos[0], 0.9), (sample_skos[1], 0.1)]
        compressed = cc.compress("JWT bypass", results)
        assert len(compressed) > 0

    def test_compress_extractive(self, sample_skos) -> None:
        cc = ContextCompressor(strategy="extractive")
        results = [(s, 1.0) for s in sample_skos[:2]]
        compressed = cc.compress("SQL injection prevention", results)
        assert "SQL" in compressed or "sql" in compressed.lower()

    def test_invalid_strategy(self) -> None:
        cc = ContextCompressor()
        with pytest.raises(ValueError):
            cc.strategy = "invalid"

    def test_strategy_setter(self) -> None:
        cc = ContextCompressor()
        cc.strategy = "threshold"
        assert cc.strategy == "threshold"

    def test_compress_chunks(self) -> None:
        cc = ContextCompressor(strategy="top_k")
        chunks = [
            Chunk(text="authentication bypass techniques", index=0),
            Chunk(text="unrelated content", index=1),
        ]
        result = cc.compress_chunks("authentication", chunks)
        assert len(result) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# CitationTracker
# ═══════════════════════════════════════════════════════════════════════════════


class TestCitationTracker:
    def test_empty(self) -> None:
        ct = CitationTracker()
        assert ct.format_citations() == ""

    def test_record_and_format_markdown(self, sample_skos) -> None:
        ct = CitationTracker()
        results = [(sample_skos[0], 0.95), (sample_skos[1], 0.80)]
        group = ct.record("JWT bypass", results)
        assert len(group.citations) == 2
        assert group.query == "JWT bypass"
        output = ct.format_citations()
        assert "JWT Authentication Bypass" in output

    def test_format_json(self, sample_skos) -> None:
        ct = CitationTracker()
        ct.set_format("json")
        ct.record("test", [(sample_skos[0], 0.95)])
        output = ct.format_citations()
        assert '"source_title"' in output

    def test_format_text(self, sample_skos) -> None:
        ct = CitationTracker()
        ct.set_format("text")
        ct.record("test", [(sample_skos[0], 0.95)])
        output = ct.format_citations()
        assert "Sources for:" in output

    def test_invalid_format(self) -> None:
        ct = CitationTracker()
        with pytest.raises(ValueError):
            ct.set_format("invalid")

    def test_history(self, sample_skos) -> None:
        ct = CitationTracker()
        ct.record("q1", [(sample_skos[0], 0.9)])
        ct.record("q2", [(sample_skos[1], 0.8)])
        hist = ct.get_history(1)
        assert len(hist) == 1
        assert hist[0].query == "q2"

    def test_clear(self, sample_skos) -> None:
        ct = CitationTracker()
        ct.record("q1", [(sample_skos[0], 0.9)])
        assert len(ct.get_history(10)) == 1
        ct.clear()
        assert len(ct.get_history(10)) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# IncrementalIndexer
# ═══════════════════════════════════════════════════════════════════════════════


class StubStore:
    def __init__(self, skos: list[SecurityKnowledgeObject]) -> None:
        self._skos = {s.id: s for s in skos}

    def list_all(self) -> list[SecurityKnowledgeObject]:
        return list(self._skos.values())

    def get(self, sko_id: str) -> SecurityKnowledgeObject | None:
        return self._skos.get(sko_id)

    def add(self, sko: SecurityKnowledgeObject) -> None:
        self._skos[sko.id] = sko


class StubRetriever:
    def __init__(self) -> None:
        self._index: dict[str, list[float]] = {}

    def index(self) -> int:
        return 0

    def clear_index(self) -> None:
        self._index.clear()


class TestIncrementalIndexer:
    def test_full_index(self, sample_skos) -> None:
        store = StubStore(sample_skos)
        config = RAGConfig(embedding_model="random")
        indexer = IncrementalIndexer(config, store)
        retriever = StubRetriever()
        result = indexer.build_full_index(retriever)
        assert result["indexed"] == 4
        assert indexer.total_indexed == 4

    def test_needs_rebuild(self, sample_skos) -> None:
        store = StubStore(sample_skos)
        config = RAGConfig(embedding_model="random")
        indexer = IncrementalIndexer(config, store)
        assert indexer.needs_rebuild() is True
        retriever = StubRetriever()
        indexer.build_full_index(retriever)
        assert indexer.needs_rebuild() is False

    def test_needs_rebuild_force(self, sample_skos) -> None:
        store = StubStore(sample_skos)
        config = RAGConfig(embedding_model="random")
        indexer = IncrementalIndexer(config, store)
        retriever = StubRetriever()
        indexer.build_full_index(retriever)
        assert indexer.needs_rebuild(force=True) is True

    def test_clear(self, sample_skos) -> None:
        store = StubStore(sample_skos)
        config = RAGConfig(embedding_model="random")
        indexer = IncrementalIndexer(config, store)
        retriever = StubRetriever()
        indexer.build_full_index(retriever)
        assert indexer.total_indexed == 4
        indexer.clear()
        assert indexer.total_indexed == 0
        assert indexer.last_indexed_at is None

    def test_last_indexed_at(self, sample_skos) -> None:
        store = StubStore(sample_skos)
        config = RAGConfig(embedding_model="random")
        indexer = IncrementalIndexer(config, store)
        assert indexer.last_indexed_at is None
        retriever = StubRetriever()
        indexer.build_full_index(retriever)
        assert indexer.last_indexed_at is not None


# ═══════════════════════════════════════════════════════════════════════════════
# RAGConfig extended fields
# ═══════════════════════════════════════════════════════════════════════════════


class TestRAGConfigAdvanced:
    def test_defaults(self) -> None:
        cfg = RAGConfig()
        assert cfg.enable_hybrid is True
        assert cfg.enable_reranking is True
        assert cfg.enable_metadata_filter is True
        assert cfg.enable_citations is True
        assert cfg.enable_incremental_index is True
        assert cfg.bm25_weight == 0.5
        assert cfg.vector_weight == 0.5
        assert cfg.chunk_size == 512
        assert cfg.chunk_overlap == 64
        assert cfg.max_context_length == 4096
        assert cfg.compression_ratio == 0.5

    def test_custom_values(self) -> None:
        cfg = RAGConfig(
            enable_hybrid=False,
            enable_reranking=False,
            bm25_weight=0.7,
            vector_weight=0.3,
            chunk_size=256,
            chunk_overlap=32,
            max_context_length=2048,
            compression_ratio=0.3,
        )
        assert cfg.enable_hybrid is False
        assert cfg.bm25_weight == 0.7
        assert cfg.chunk_size == 256
        assert cfg.compression_ratio == 0.3

    def test_rerank_top_k_defaults(self) -> None:
        cfg = RAGConfig()
        assert cfg.rerank_top_k == 20
        assert cfg.final_top_k == 5
