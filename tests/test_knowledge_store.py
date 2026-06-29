"""Tests for the KnowledgeStore."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deephunter.core.exceptions import StorageError
from deephunter.core.types import BugClass, SourceType
from deephunter.knowledge.models import SKOBuilder, SecurityKnowledgeObject


class TestKnowledgeStore:
    def test_count_empty(self, empty_store) -> None:
        assert empty_store.count() == 0

    def test_add_and_count(self, empty_store) -> None:
        sko = SKOBuilder().title("Test").source("test").build()
        sko_id = empty_store.add(sko)
        assert empty_store.count() == 1
        assert sko_id == sko.id

    def test_add_duplicate_id(self, empty_store) -> None:
        sko = SKOBuilder().title("A").source("test").build()
        empty_store.add(sko)
        with pytest.raises(StorageError, match="already exists"):
            empty_store.add(sko)

    def test_get_existing(self, populated_store) -> None:
        skos = populated_store.list_all()
        sko = populated_store.get(skos[0].id)
        assert sko is not None
        assert sko.title == skos[0].title

    def test_get_nonexistent(self, populated_store) -> None:
        assert populated_store.get("nonexistent") is None

    def test_update(self, empty_store) -> None:
        sko = SKOBuilder().title("Original").source("test").build()
        empty_store.add(sko)

        sko.title = "Updated"
        empty_store.update(sko)
        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.title == "Updated"

    def test_update_nonexistent(self, empty_store) -> None:
        sko = SKOBuilder().title("Ghost").source("test").build()
        with pytest.raises(StorageError, match="not found"):
            empty_store.update(sko)

    def test_delete(self, empty_store) -> None:
        sko = SKOBuilder().title("Delete me").source("test").build()
        empty_store.add(sko)
        assert empty_store.delete(sko.id) is True
        assert empty_store.count() == 0

    def test_delete_nonexistent(self, empty_store) -> None:
        assert empty_store.delete("nonexistent") is False

    def test_clear(self, populated_store) -> None:
        assert populated_store.count() == 3
        populated_store.clear()
        assert populated_store.count() == 0

    def test_list_all(self, populated_store) -> None:
        skos = populated_store.list_all()
        assert len(skos) == 3

    def test_add_batch(self, empty_store) -> None:
        skos = [
            SKOBuilder().title("A").source("a").build(),
            SKOBuilder().title("B").source("b").build(),
            SKOBuilder().title("C").source("c").build(),
        ]
        ids = empty_store.add_batch(skos)
        assert len(ids) == 3
        assert empty_store.count() == 3

    def test_add_batch_collision(self, empty_store) -> None:
        sko = SKOBuilder().title("A").source("a").build()
        empty_store.add(sko)
        with pytest.raises(StorageError, match="already exists"):
            empty_store.add_batch([sko])

    def test_search_by_title(self, populated_store) -> None:
        results = populated_store.search_by_title("JWT")
        assert len(results) == 1
        assert results[0].title == "JWT Authentication Bypass"

    def test_search_by_title_case_insensitive(self, populated_store) -> None:
        results = populated_store.search_by_title("jwt")
        assert len(results) == 1

    def test_search_by_title_case_sensitive(self, populated_store) -> None:
        results = populated_store.search_by_title("jwt", case_sensitive=True)
        assert len(results) == 0

    def test_search_by_tag(self, populated_store) -> None:
        results = populated_store.search_by_tag("jwt")
        assert len(results) == 1
        assert "jwt" in results[0].tags

    def test_search_by_tag_nonexistent(self, populated_store) -> None:
        results = populated_store.search_by_tag("nonexistent")
        assert len(results) == 0

    def test_search_by_bug_class(self, populated_store) -> None:
        results = populated_store.search_by_bug_class("sql_injection")
        assert len(results) == 1

    def test_search_by_bug_class_nonexistent(self, populated_store) -> None:
        results = populated_store.search_by_bug_class("ssrf")
        assert len(results) == 0

    def test_search_raw_content(self, populated_store) -> None:
        results = populated_store.search_raw_content("JWT")
        assert len(results) == 1

    def test_search_raw_content_no_match(self, populated_store) -> None:
        results = populated_store.search_raw_content("nonexistent content here")
        assert len(results) == 0

    def test_search_source_type(self, populated_store) -> None:
        results = populated_store.search_source_type("owasp")
        assert len(results) == 2

    def test_save_and_load(self, populated_store, tmp_path: Path) -> None:
        path = tmp_path / "skos.json"
        populated_store.save(str(path))
        assert path.exists()

        new_store = type(populated_store)()
        count = new_store.load(str(path))
        assert count == 3

        original_titles = {s.title for s in populated_store.list_all()}
        loaded_titles = {s.title for s in new_store.list_all()}
        assert original_titles == loaded_titles

    def test_load_nonexistent(self, empty_store) -> None:
        with pytest.raises(StorageError, match="not found"):
            empty_store.load("/nonexistent/file.json")

    def test_save_no_path(self, empty_store) -> None:
        with pytest.raises(StorageError, match="No persist path"):
            empty_store.save()