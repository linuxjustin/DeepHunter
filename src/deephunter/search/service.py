"""Unified Search Service.

Provides cross-entity search across all workspace entities including notebook,
evidence, endpoints, tasks, reports, and conversations.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from deephunter.investigation.models import EvidenceRecord
from deephunter.investigation.notebook.models import NotebookEntry
from deephunter.investigation.taskboard.models import BoardCard, BoardColumn, TaskPriority, TaskStatus
from deephunter.reasoning.models import Finding, Hypothesis
from deephunter.search.models import (
    SearchQuery,
    SearchResponse,
    SearchResult,
    SearchResultType,
    SearchScope,
)
from deephunter.workspace.models import Note, Report
from deephunter.utils import get_logger

logger = get_logger(__name__)


class SearchService:
    """Unified search across all investigation entities."""

    def __init__(self) -> None:
        self._notebook: list[NotebookEntry] = []
        self._notes: list[Note] = []
        self._evidence: list[EvidenceRecord] = []
        self._endpoints: list[Any] = []
        self._parameters: list[Any] = []
        self._technologies: list[Any] = []
        self._tasks: list[BoardCard] = []
        self._findings: list[Finding] = []
        self._hypotheses: list[Hypothesis] = []
        self._reports: list[Report] = []
        self._knowledge_packs: list[Any] = []
        self._methodology_packs: list[Any] = []
        self._conversations: list[Any] = []

    def index_notebook_entries(self, entries: list[NotebookEntry]) -> None:
        self._notebook = entries

    def index_notes(self, notes: list[Note]) -> None:
        self._notes = notes

    def index_evidence(self, evidence: list[EvidenceRecord]) -> None:
        self._evidence = evidence

    def index_endpoints(self, endpoints: list[Any]) -> None:
        self._endpoints = endpoints

    def index_parameters(self, parameters: list[Any]) -> None:
        self._parameters = parameters

    def index_technologies(self, technologies: list[Any]) -> None:
        self._technologies = technologies

    def index_tasks(self, tasks: list[BoardCard]) -> None:
        self._tasks = tasks

    def index_findings(self, findings: list[Finding]) -> None:
        self._findings = findings

    def index_hypotheses(self, hypotheses: list[Hypothesis]) -> None:
        self._hypotheses = hypotheses

    def index_reports(self, reports: list[Report]) -> None:
        self._reports = reports

    def index_conversations(self, conversations: list[Any]) -> None:
        self._conversations = conversations

    def search(self, query: SearchQuery) -> SearchResponse:
        start = time.monotonic()
        results: list[SearchResult] = []
        query_str = query.query.lower().strip()

        if not query_str:
            return SearchResponse(
                query=query.query,
                total_results=0,
                results=[],
                execution_time_ms=(time.monotonic() - start) * 1000,
            )

        if SearchScope.ALL in query.scopes or SearchScope.NOTEBOOK in query.scopes:
            results.extend(self._search_notebook(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.EVIDENCE in query.scopes:
            results.extend(self._search_evidence(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.TASKS in query.scopes:
            results.extend(self._search_tasks(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.FINDINGS in query.scopes:
            results.extend(self._search_findings(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.HYPOTHESES in query.scopes:
            results.extend(self._search_hypotheses(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.REPORTS in query.scopes:
            results.extend(self._search_reports(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.ENDPOINTS in query.scopes:
            results.extend(self._search_endpoints(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.PARAMETERS in query.scopes:
            results.extend(self._search_parameters(query_str, query))

        if SearchScope.ALL in query.scopes or SearchScope.TECHNOLOGIES in query.scopes:
            results.extend(self._search_technologies(query_str, query))

        results = sorted(results, key=lambda r: r.relevance_score, reverse=True)

        total = len(results)
        paginated = results[query.offset : query.offset + query.limit]

        suggestions = self._generate_suggestions(query_str, results)

        return SearchResponse(
            query=query.query,
            total_results=total,
            results=paginated,
            execution_time_ms=(time.monotonic() - start) * 1000,
            pagination={
                "limit": query.limit,
                "offset": query.offset,
                "total": total,
                "has_more": query.offset + query.limit < total,
            },
            suggestions=suggestions,
        )

    def _score(self, text: str, query: str) -> float:
        text_lower = text.lower()
        query_lower = query.lower()
        if query_lower in text_lower:
            return 1.0
        words = query_lower.split()
        matched = sum(1 for w in words if w in text_lower)
        if matched > 0:
            return matched / len(words) * 0.9
        return 0.0

    def _snippet(self, text: str, query: str, length: int = 200) -> str:
        text_lower = text.lower()
        idx = text_lower.find(query.lower())
        if idx >= 0:
            start = max(0, idx - 50)
            end = min(len(text), idx + length)
            snippet = text[start:end]
            if start > 0:
                snippet = "..." + snippet
            if end < len(text):
                snippet = snippet + "..."
            return snippet
        return text[:length] + ("..." if len(text) > length else "")

    def _search_notebook(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for entry in self._notebook:
            if sq.target_id and entry.target_id != sq.target_id:
                continue
            if sq.tags:
                if not any(t in entry.tags for t in sq.tags):
                    continue
            score = max(
                self._score(entry.title, query),
                self._score(entry.content, query),
                self._score(" ".join(entry.tags), query),
            )
            if score > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.NOTEBOOK_ENTRY,
                    result_id=entry.id,
                    title=entry.title,
                    description=entry.entry_type.value,
                    content_snippet=self._snippet(entry.content, query),
                    relevance_score=score,
                    target_id=entry.target_id,
                    investigation_session_id=entry.investigation_session_id,
                    url_path=f"/notebook/entries/{entry.id}",
                    created_at=entry.created_at,
                    updated_at=entry.updated_at,
                    tags=entry.tags,
                ))
        return results

    def _search_evidence(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for ev in self._evidence:
            score = max(
                self._score(getattr(ev, "title", ""), query),
                self._score(getattr(ev, "description", ""), query),
                self._score(getattr(ev, "content", ""), query),
            )
            if score > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.EVIDENCE,
                    result_id=ev.id if hasattr(ev, "id") else "",
                    title=getattr(ev, "title", "Untitled Evidence"),
                    description=getattr(ev, "type", "evidence"),
                    content_snippet=self._snippet(getattr(ev, "description", ""), query),
                    relevance_score=score,
                    url_path=f"/evidence/{ev.id if hasattr(ev, 'id') else ''}",
                    created_at=getattr(ev, "created_at", None),
                    tags=getattr(ev, "tags", []),
                ))
        return results

    def _search_tasks(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for task in self._tasks:
            if sq.target_id and task.target_id != sq.target_id:
                continue
            score = max(
                self._score(task.title, query),
                self._score(task.description, query),
                self._score(task.findings, query),
                self._score(" ".join(task.tags), query),
            )
            if score > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.TASK,
                    result_id=task.id,
                    title=task.title,
                    description=f"[{task.column.value}] {task.priority.value}",
                    content_snippet=self._snippet(task.description, query),
                    relevance_score=score,
                    target_id=task.target_id,
                    investigation_session_id=task.investigation_session_id,
                    url_path=f"/tasks/{task.id}",
                    created_at=task.created_at,
                    updated_at=task.updated_at,
                    tags=task.tags,
                ))
        return results

    def _search_findings(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for finding in self._findings:
            score = max(
                self._score(getattr(finding, "title", ""), query),
                self._score(getattr(finding, "description", ""), query),
            )
            if score > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.FINDING,
                    result_id=finding.id if hasattr(finding, "id") else "",
                    title=getattr(finding, "title", "Untitled"),
                    description=f"Severity: {getattr(finding, 'severity', 'unknown')}",
                    content_snippet=self._snippet(getattr(finding, "description", ""), query),
                    relevance_score=score,
                    url_path=f"/findings/{finding.id if hasattr(finding, 'id') else ''}",
                    tags=getattr(finding, "tags", []),
                ))
        return results

    def _search_hypotheses(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for hyp in self._hypotheses:
            score = max(
                self._score(getattr(hyp, "title", ""), query),
                self._score(getattr(hyp, "description", ""), query),
                self._score(getattr(hyp, "rationale", ""), query),
            )
            if score > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.HYPOTHESIS,
                    result_id=hyp.id if hasattr(hyp, "id") else "",
                    title=getattr(hyp, "title", "Untitled Hypothesis"),
                    description=f"Status: {getattr(hyp, 'status', 'proposed')}",
                    content_snippet=self._snippet(getattr(hyp, "description", ""), query),
                    relevance_score=score,
                    url_path=f"/hypotheses/{hyp.id if hasattr(hyp, 'id') else ''}",
                    created_at=getattr(hyp, "created_at", None),
                    tags=[],
                ))
        return results

    def _search_reports(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for report in self._reports:
            if sq.target_id and getattr(report, "target_id", "") != sq.target_id:
                continue
            score = max(
                self._score(getattr(report, "title", ""), query),
                self._score(getattr(report, "content", ""), query),
            )
            if score > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.REPORT,
                    result_id=report.id,
                    title=getattr(report, "title", "Untitled Report"),
                    description=f"Format: {getattr(report, 'format', 'markdown')}",
                    content_snippet=self._snippet(getattr(report, "content", ""), query),
                    relevance_score=score,
                    target_id=getattr(report, "target_id", ""),
                    url_path=f"/reports/{report.id}",
                    created_at=getattr(report, "generated_at", None),
                    tags=getattr(report, "tags", []),
                ))
        return results

    def _search_endpoints(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for ep in self._endpoints:
            url = getattr(ep, "url", getattr(ep, "path", ""))
            method = getattr(ep, "method", "")
            score = self._score(url, query) + (0.5 if method.lower() in query.lower() else 0)
            if score > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.ENDPOINT,
                    result_id=ep.id if hasattr(ep, "id") else "",
                    title=f"{method} {url}" if method else url,
                    description=getattr(ep, "category", ""),
                    relevance_score=score,
                    url_path=f"/endpoints/{ep.id if hasattr(ep, 'id') else ''}",
                    tags=getattr(ep, "tags", []),
                ))
        return results

    def _search_parameters(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for param in self._parameters:
            name = getattr(param, "name", "")
            if self._score(name, query) > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.PARAMETER,
                    result_id=param.id if hasattr(param, "id") else "",
                    title=f"Parameter: {name}",
                    description=f"Location: {getattr(param, 'location', '')}",
                    relevance_score=self._score(name, query),
                    url_path=f"/parameters/{param.id if hasattr(param, 'id') else ''}",
                ))
        return results

    def _search_technologies(self, query: str, sq: SearchQuery) -> list[SearchResult]:
        results = []
        for tech in self._technologies:
            name = getattr(tech, "name", "")
            if self._score(name, query) > 0:
                results.append(SearchResult(
                    result_type=SearchResultType.TECHNOLOGY,
                    result_id=tech.id if hasattr(tech, "id") else "",
                    title=name,
                    description=getattr(tech, "category", ""),
                    relevance_score=self._score(name, query),
                    url_path=f"/technologies/{tech.id if hasattr(tech, 'id') else ''}",
                ))
        return results

    def _generate_suggestions(self, query: str, results: list[SearchResult]) -> list[str]:
        suggestions = []
        if len(results) < 3:
            words = query.split()
            if len(words) > 1:
                suggestions.append(" ".join(words[1:]))
        return suggestions