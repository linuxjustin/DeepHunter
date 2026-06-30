"""Tests for the KnowledgeStore."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from deephunter.core.exceptions import StorageError
from deephunter.knowledge.models import SecurityKnowledgeObject, SKOCurationStatus
from deephunter.knowledge.store import KnowledgeStore


class TestKnowledgeStore:
    def test_count_empty(self, empty_store) -> None:
        assert empty_store.count() == 0

    def _make_sko(self, title: str, source: str = "https://test.com") -> SecurityKnowledgeObject:
        return SecurityKnowledgeObject(title=title, source=source)

    def test_add_and_count(self, empty_store) -> None:
        sko = self._make_sko("Test")
        sko_id = empty_store.add(sko)
        assert empty_store.count() == 1
        assert sko_id == sko.id

    def test_add_duplicate_id(self, empty_store) -> None:
        sko = self._make_sko("A")
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
        sko = self._make_sko("Original")
        empty_store.add(sko)

        sko.title = "Updated"
        empty_store.update(sko)
        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.title == "Updated"

    def test_update_nonexistent(self, empty_store) -> None:
        sko = self._make_sko("Ghost")
        with pytest.raises(StorageError, match="not found"):
            empty_store.update(sko)

    def test_delete(self, empty_store) -> None:
        sko = self._make_sko("Delete me")
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
            self._make_sko("A", "https://test.com/a"),
            self._make_sko("B", "https://test.com/b"),
            self._make_sko("C", "https://test.com/c"),
        ]
        ids = empty_store.add_batch(skos)
        assert len(ids) == 3
        assert empty_store.count() == 3

    def test_add_batch_collision(self, empty_store) -> None:
        sko = self._make_sko("A", "https://test.com/a")
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
        # SQLite store auto-persists; save() is a no-op for backward compat
        populated_store.save()

        new_store = KnowledgeStore(str(populated_store._db_path))
        count = new_store.load()
        assert count == 3

        original_titles = {s.title for s in populated_store.list_all()}
        loaded_titles = {s.title for s in new_store.list_all()}
        assert original_titles == loaded_titles

    def test_load_nonexistent(self) -> None:
        from deephunter.knowledge.store import KnowledgeStore
        store = KnowledgeStore("/nonexistent/db/store.db")
        store._db_path.parent.mkdir(parents=True, exist_ok=True)
        # A fresh SQLite store loads fine (creates new DB)
        assert store.load() == 0

    def test_save_no_path(self, empty_store) -> None:
        # SQLite store auto-persists; save() does not require a path
        empty_store.save()


class TestCurationWorkflow:
    def _make_sko(self, title: str, source: str = "https://test.com") -> SecurityKnowledgeObject:
        return SecurityKnowledgeObject(title=title, source=source)

    def test_default_curation_status_is_draft(self, empty_store) -> None:
        sko = self._make_sko("Draft Test")
        empty_store.add(sko)
        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.curation_status == SKOCurationStatus.DRAFT

    def test_get_by_curation_status(self, empty_store) -> None:
        sko1 = self._make_sko("Draft SKO")
        sko2 = self._make_sko("Review SKO")
        sko3 = self._make_sko("Approved SKO")
        empty_store.add(sko1)
        empty_store.add(sko2)
        empty_store.add(sko3)

        empty_store.submit_for_review(sko2.id, "alice", "Please review")
        empty_store.approve_sko(sko3.id, "bob")

        drafts = empty_store.get_by_curation_status(SKOCurationStatus.DRAFT)
        assert len(drafts) == 1
        assert drafts[0].title == "Draft SKO"

        under_review = empty_store.get_by_curation_status(SKOCurationStatus.UNDER_REVIEW)
        assert len(under_review) == 1
        assert under_review[0].title == "Review SKO"

        approved = empty_store.get_by_curation_status(SKOCurationStatus.APPROVED)
        assert len(approved) == 1
        assert approved[0].title == "Approved SKO"

    def test_submit_for_review(self, empty_store) -> None:
        sko = self._make_sko("Submit Test")
        empty_store.add(sko)

        result = empty_store.submit_for_review(sko.id, "alice", "Review me")
        assert result is True

        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.curation_status == SKOCurationStatus.UNDER_REVIEW
        assert retrieved.curator == "alice"
        assert retrieved.curation_notes == "Review me"

    def test_submit_for_review_nonexistent(self, empty_store) -> None:
        result = empty_store.submit_for_review("nonexistent-id", "alice")
        assert result is False

    def test_approve_sko(self, empty_store) -> None:
        sko = self._make_sko("Approve Test")
        empty_store.add(sko)

        result = empty_store.approve_sko(sko.id, "bob", "LGTM")
        assert result is True

        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.curation_status == SKOCurationStatus.APPROVED
        assert retrieved.reviewed_by == "bob"
        assert retrieved.curation_notes == "LGTM"
        assert retrieved.reviewed_at is not None

    def test_approve_sko_with_notes_append(self, empty_store) -> None:
        sko = self._make_sko("Approve Notes")
        empty_store.add(sko)
        empty_store.submit_for_review(sko.id, "alice", "Initial notes")

        empty_store.approve_sko(sko.id, "bob")
        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.curation_status == SKOCurationStatus.APPROVED
        assert retrieved.curation_notes == "Initial notes"

    def test_approve_sko_nonexistent(self, empty_store) -> None:
        result = empty_store.approve_sko("nonexistent-id", "bob")
        assert result is False

    def test_deprecate_sko(self, empty_store) -> None:
        sko = self._make_sko("Deprecate Test")
        empty_store.add(sko)
        empty_store.approve_sko(sko.id, "bob")

        result = empty_store.deprecate_sko(sko.id, "charlie", "Outdated")
        assert result is True

        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.curation_status == SKOCurationStatus.DEPRECATED
        assert retrieved.reviewed_by == "charlie"
        assert retrieved.curation_notes == "Outdated"

    def test_deprecate_sko_nonexistent(self, empty_store) -> None:
        result = empty_store.deprecate_sko("nonexistent-id", "charlie")
        assert result is False

    def test_archive_sko(self, empty_store) -> None:
        sko = self._make_sko("Archive Test")
        empty_store.add(sko)

        result = empty_store.archive_sko(sko.id)
        assert result is True

        retrieved = empty_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.curation_status == SKOCurationStatus.ARCHIVED

    def test_archive_sko_nonexistent(self, empty_store) -> None:
        result = empty_store.archive_sko("nonexistent-id")
        assert result is False

    def test_full_curation_workflow(self, empty_store) -> None:
        sko = self._make_sko("Full Workflow")
        empty_store.add(sko)

        assert empty_store.get(sko.id).curation_status == SKOCurationStatus.DRAFT

        empty_store.submit_for_review(sko.id, "alice", "Ready for review")
        assert empty_store.get(sko.id).curation_status == SKOCurationStatus.UNDER_REVIEW

        empty_store.approve_sko(sko.id, "bob", "Looks good")
        assert empty_store.get(sko.id).curation_status == SKOCurationStatus.APPROVED

        empty_store.deprecate_sko(sko.id, "charlie", "Needs update")
        assert empty_store.get(sko.id).curation_status == SKOCurationStatus.DEPRECATED

        empty_store.archive_sko(sko.id)
        assert empty_store.get(sko.id).curation_status == SKOCurationStatus.ARCHIVED

    def test_get_curation_summary(self, empty_store) -> None:
        sko1 = self._make_sko("Draft 1")
        sko2 = self._make_sko("Draft 2")
        sko3 = self._make_sko("Under Review")
        sko4 = self._make_sko("Approved")
        empty_store.add(sko1)
        empty_store.add(sko2)
        empty_store.add(sko3)
        empty_store.add(sko4)

        empty_store.submit_for_review(sko3.id, "alice")
        empty_store.approve_sko(sko4.id, "bob")

        summary = empty_store.get_curation_summary()
        assert summary.get("draft") == 2
        assert summary.get("under_review") == 1
        assert summary.get("approved") == 1

    def test_get_curation_summary_empty(self, empty_store) -> None:
        summary = empty_store.get_curation_summary()
        assert summary == {}

    def test_curation_persists_after_reload(self, empty_store, tmp_path: Path) -> None:
        sko = self._make_sko("Persist Test")
        empty_store.add(sko)
        empty_store.submit_for_review(sko.id, "alice", "Review me")
        empty_store.approve_sko(sko.id, "bob", "LGTM")

        new_store = KnowledgeStore(str(empty_store._db_path))
        retrieved = new_store.get(sko.id)
        assert retrieved is not None
        assert retrieved.curation_status == SKOCurationStatus.APPROVED
        assert retrieved.curator == "alice"
        assert retrieved.reviewed_by == "bob"
        assert retrieved.curation_notes == "LGTM"
