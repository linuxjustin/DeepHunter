"""End-to-end integration test: ingest → search → hypothesize."""

from __future__ import annotations

from pathlib import Path

from deephunter.core.config import DeepHunterConfig
from deephunter.core.types import BugClass
from deephunter.ingestion.pipeline import IngestionPipeline
from deephunter.knowledge.store import KnowledgeStore
from deephunter.parsers.base import ParserRegistry
from deephunter.parsers.markdown_parser import MarkdownParser
from deephunter.rag.embeddings import RandomEmbeddingProvider
from deephunter.rag.retriever import Retriever
from deephunter.reasoning.hypothesis import HypothesisGenerator


def test_ingest_search_hypothesize(tmp_path: Path) -> None:
    config = DeepHunterConfig.default()

    store = KnowledgeStore(str(tmp_path / "store.db"))

    registry = ParserRegistry()
    registry.register(MarkdownParser())

    pipeline = IngestionPipeline(config, store, parser_registry=registry)

    content = """# SQL Injection and JWT Security Testing

## Overview
SQL injection remains a critical vulnerability in web applications.

## Common Vulnerabilities
- Classic SQLi: `' OR '1'='1`
- Blind SQLi: Time-based and boolean-based
- JWT algorithm confusion attacks (RS256 → HS256)

## Technologies
nodejs, express, react

## Prevention
Use parameterized queries and input validation.
"""
    file_path = tmp_path / "jwt_security.md"
    file_path.write_text(content)

    sko = pipeline.parse_single(str(file_path))
    assert sko is not None
    assert "SQL injection" in sko.raw_content
    assert "SQL injection" in sko.summary
    assert BugClass.SQL_INJECTION in sko.bug_classes

    store.add(sko)
    assert store.count() == 1

    retrieved = store.search_by_title("jwt")
    assert len(retrieved) == 1
    assert retrieved[0].id == sko.id

    retriever = Retriever(config.rag, store, embedding_provider=RandomEmbeddingProvider())
    indexed = retriever.index()
    assert indexed >= 1

    results = retriever.query("JWT authentication tokens", threshold=0.0)
    assert len(results) >= 1
    assert results[0][0].id == sko.id
    assert results[0][1] != 0.0

    gen = HypothesisGenerator(store, retriever, config.reasoning)
    hypotheses = gen.generate("JWT authentication security")
    assert len(hypotheses) >= 1
    assert any("sql" in h.title.lower() or "injection" in h.title.lower() for h in hypotheses)
