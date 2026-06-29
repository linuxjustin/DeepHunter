"""Tests for deduplication."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.ingestion.dedup import (
    ContentHashDedup,
    DeduplicationEngine,
    DeduplicationStrategy,
    NoOpDedup,
)
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore


class TestContentHashDedup:
    def test_same_content_is_duplicate(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        dedup = ContentHashDedup()

        sko1 = SecurityKnowledgeObject(
            title="A",
            source="https://a.com",
            normalized_content="hello world",
        )
        sko2 = SecurityKnowledgeObject(
            title="B",
            source="https://b.com",
            normalized_content="hello world",
        )

        store.add(sko1)
        result = dedup.is_duplicate(sko2, store)
        assert result.is_duplicate is True
        assert result.strategy == "content_hash"
        assert result.existing_id == sko1.id

    def test_different_content_not_duplicate(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        dedup = ContentHashDedup()

        sko1 = SecurityKnowledgeObject(
            title="A",
            source="https://a.com",
            normalized_content="hello world",
        )
        sko2 = SecurityKnowledgeObject(
            title="B",
            source="https://b.com",
            normalized_content="goodbye world",
        )

        store.add(sko1)
        result = dedup.is_duplicate(sko2, store)
        assert result.is_duplicate is False

    def test_fallback_to_raw_content(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        dedup = ContentHashDedup()

        sko1 = SecurityKnowledgeObject(
            title="A",
            source="https://a.com",
            raw_content="raw content",
        )
        sko2 = SecurityKnowledgeObject(
            title="B",
            source="https://b.com",
            raw_content="raw content",
        )

        store.add(sko1)
        result = dedup.is_duplicate(sko2, store)
        assert result.is_duplicate is True

    def test_empty_store(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        dedup = ContentHashDedup()

        sko = SecurityKnowledgeObject(title="A", source="https://a.com")
        result = dedup.is_duplicate(sko, store)
        assert result.is_duplicate is False

    def test_empty_content(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        dedup = ContentHashDedup()

        sko1 = SecurityKnowledgeObject(title="A", source="https://a.com")
        sko2 = SecurityKnowledgeObject(title="B", source="https://b.com")

        store.add(sko1)
        result = dedup.is_duplicate(sko2, store)
        assert result.is_duplicate is True  # both have empty content → same hash


class TestNoOpDedup:
    def test_never_duplicate(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        dedup = NoOpDedup()

        sko1 = SecurityKnowledgeObject(title="A", source="https://a.com")
        sko2 = SecurityKnowledgeObject(title="A", source="https://a.com")  # same everything

        store.add(sko1)
        result = dedup.is_duplicate(sko2, store)
        assert result.is_duplicate is False
        assert result.strategy == "noop"


class TestDeduplicationEngine:
    def test_any_strategy_triggers_duplicate(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        engine = DeduplicationEngine(
            strategies=[ContentHashDedup()],
        )

        sko1 = SecurityKnowledgeObject(
            title="A",
            source="https://a.com",
            normalized_content="same",
        )
        sko2 = SecurityKnowledgeObject(
            title="B",
            source="https://b.com",
            normalized_content="same",
        )

        store.add(sko1)
        result = engine.is_duplicate(sko2, store)
        assert result.is_duplicate is True

    def test_no_strategies(self, tmp_path: Path) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        engine = DeduplicationEngine(strategies=[])
        sko = SecurityKnowledgeObject(title="A", source="https://a.com")
        result = engine.is_duplicate(sko, store)
        assert result.is_duplicate is False
