"""Tests for JSONKnowledgeStore."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.core.exceptions import StorageError
from deephunter.knowledge.json_store import JSONKnowledgeStore
from deephunter.knowledge.models import SecurityKnowledgeObject


class TestJSONKnowledgeStore:
    def test_add_and_get(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        sko = SecurityKnowledgeObject(title="Test", source="https://test.com")
        sko_id = store.add(sko)
        assert sko_id == sko.id

        retrieved = store.get(sko.id)
        assert retrieved is not None
        assert retrieved.title == "Test"

    def test_add_duplicate_raises(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        sko = SecurityKnowledgeObject(title="A", source="https://a.com")
        store.add(sko)
        with pytest.raises(StorageError, match="already exists"):
            store.add(sko)

    def test_get_nonexistent(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        assert store.get("nonexistent") is None

    def test_update(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        sko = SecurityKnowledgeObject(title="Original", source="https://test.com")
        store.add(sko)

        sko.title = "Updated"
        store.update(sko)
        retrieved = store.get(sko.id)
        assert retrieved is not None
        assert retrieved.title == "Updated"

    def test_update_nonexistent_raises(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        sko = SecurityKnowledgeObject(title="Ghost", source="https://test.com")
        with pytest.raises(StorageError, match="not found"):
            store.update(sko)

    def test_delete(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        sko = SecurityKnowledgeObject(title="To Delete", source="https://test.com")
        store.add(sko)
        assert store.delete(sko.id) is True
        assert store.get(sko.id) is None

    def test_delete_nonexistent(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        assert store.delete("nonexistent") is False

    def test_count(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        assert store.count() == 0

        store.add(SecurityKnowledgeObject(title="A", source="https://a.com"))
        store.add(SecurityKnowledgeObject(title="B", source="https://b.com"))
        assert store.count() == 2

    def test_list_all(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        sko1 = SecurityKnowledgeObject(title="A", source="https://a.com")
        sko2 = SecurityKnowledgeObject(title="B", source="https://b.com")
        store.add(sko1)
        store.add(sko2)

        all_skos = store.list_all()
        assert len(all_skos) == 2
        titles = {s.title for s in all_skos}
        assert titles == {"A", "B"}

    def test_clear(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        store.add(SecurityKnowledgeObject(title="A", source="https://a.com"))
        store.add(SecurityKnowledgeObject(title="B", source="https://b.com"))
        assert store.count() == 2
        store.clear()
        assert store.count() == 0

    def test_add_batch(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        skos = [
            SecurityKnowledgeObject(title="A", source="https://a.com"),
            SecurityKnowledgeObject(title="B", source="https://b.com"),
        ]
        ids = store.add_batch(skos)
        assert len(ids) == 2
        assert store.count() == 2

    def test_search_by_title(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        store.add(SecurityKnowledgeObject(title="JWT Attacks", source="https://test.com"))
        results = store.search_by_title("JWT")
        assert len(results) == 1

    def test_search_by_tag(self, tmp_path: Path) -> None:
        store = JSONKnowledgeStore(tmp_path)
        store.add(SecurityKnowledgeObject(
            title="Test",
            source="https://test.com",
            tags=["sqli"],
        ))
        results = store.search_by_tag("sqli")
        assert len(results) == 1
