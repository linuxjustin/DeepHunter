"""Tests for Unified Search."""

from __future__ import annotations

from deephunter.investigation.notebook.models import NotebookEntry, NoteType, NoteStatus
from deephunter.investigation.taskboard.models import BoardCard, BoardColumn, TaskPriority
from deephunter.search import SearchService, SearchScope, SearchQuery
from deephunter.search.models import SearchResult, SearchResultType


class TestSearchService:
    def test_search_empty_query(self) -> None:
        service = SearchService()
        sq = SearchQuery(query="", scopes=[SearchScope.ALL])
        result = service.search(sq)
        assert result.total_results == 0

    def test_search_notebook_entries(self) -> None:
        service = SearchService()
        entries = [
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.RESEARCH_NOTE, title="SQL Injection Analysis", content="Found SQLi in login"),
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.OBSERVATION, title="XSS Found", content="XSS in search param"),
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.HYPOTHESIS, title="IDOR Hypothesis", content="Possible IDOR in user profile"),
        ]
        service.index_notebook_entries(entries)

        sq = SearchQuery(query="SQL", scopes=[SearchScope.ALL])
        result = service.search(sq)
        assert result.total_results >= 1
        assert any("SQL" in r.title for r in result.results)

    def test_search_tasks(self) -> None:
        service = SearchService()
        tasks = [
            BoardCard(target_id="tgt-1", title="Test for SQL Injection", column=BoardColumn.BACKLOG),
            BoardCard(target_id="tgt-1", title="Test for XSS", column=BoardColumn.BACKLOG),
        ]
        service.index_tasks(tasks)

        sq = SearchQuery(query="SQL", scopes=[SearchScope.TASKS])
        result = service.search(sq)
        assert result.total_results >= 1

    def test_search_filters_by_target(self) -> None:
        service = SearchService()
        entries = [
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.RESEARCH_NOTE, title="Target 1 Note", content="Content"),
            NotebookEntry(target_id="tgt-2", entry_type=NoteType.RESEARCH_NOTE, title="Target 2 Note", content="Content"),
        ]
        service.index_notebook_entries(entries)

        sq = SearchQuery(query="Note", scopes=[SearchScope.NOTEBOOK], target_id="tgt-1")
        result = service.search(sq)
        assert all(r.target_id == "tgt-1" for r in result.results)

    def test_search_pagination(self) -> None:
        service = SearchService()
        entries = [
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.RESEARCH_NOTE, title=f"Note {i}", content="Content")
            for i in range(25)
        ]
        service.index_notebook_entries(entries)

        sq = SearchQuery(query="Note", scopes=[SearchScope.ALL], limit=10, offset=0)
        result = service.search(sq)
        assert len(result.results) == 10
        assert result.pagination["total"] == 25
        assert result.pagination["has_more"] is True

    def test_search_relevance_ordering(self) -> None:
        service = SearchService()
        entries = [
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.RESEARCH_NOTE, title="SQL", content=""),
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.RESEARCH_NOTE, title="SQL Injection", content="Detailed analysis"),
        ]
        service.index_notebook_entries(entries)

        sq = SearchQuery(query="SQL", scopes=[SearchScope.ALL])
        result = service.search(sq)
        if len(result.results) > 1:
            assert result.results[0].relevance_score >= result.results[1].relevance_score

    def test_search_with_multiple_scopes(self) -> None:
        service = SearchService()
        service.index_notebook_entries([
            NotebookEntry(target_id="tgt-1", entry_type=NoteType.RESEARCH_NOTE, title="Important Note", content="XSS content"),
        ])
        service.index_tasks([
            BoardCard(target_id="tgt-1", title="XSS Test Task", column=BoardColumn.BACKLOG),
        ])

        sq = SearchQuery(query="XSS", scopes=[SearchScope.NOTEBOOK, SearchScope.TASKS])
        result = service.search(sq)
        assert result.total_results >= 2


class TestSearchModels:
    def test_search_query_defaults(self) -> None:
        sq = SearchQuery(query="test")
        assert sq.scopes == [SearchScope.ALL]
        assert sq.limit == 20
        assert sq.offset == 0
        assert sq.include_archived is False

    def test_search_result(self) -> None:
        sr = SearchResult(
            result_type=SearchResultType.NOTEBOOK_ENTRY,
            result_id="nb-1",
            title="Test Result",
            description="A test",
            content_snippet="...matching snippet...",
            relevance_score=0.85,
            url_path="/notebook/entries/nb-1",
            tags=["important"],
        )
        assert sr.result_type == SearchResultType.NOTEBOOK_ENTRY
        assert sr.relevance_score == 0.85
        assert "important" in sr.tags

    def test_search_scopes(self) -> None:
        assert SearchScope.ALL.value == "all"
        assert SearchScope.NOTEBOOK.value == "notebook"
        assert SearchScope.TASKS.value == "tasks"
        assert SearchScope.EVIDENCE.value == "evidence"
        assert SearchScope.FINDINGS.value == "findings"
        assert SearchScope.REPORTS.value == "reports"

    def test_search_result_types(self) -> None:
        assert SearchResultType.NOTEBOOK_ENTRY.value == "notebook_entry"
        assert SearchResultType.TASK.value == "task"
        assert SearchResultType.FINDING.value == "finding"
        assert SearchResultType.EVIDENCE.value == "evidence"