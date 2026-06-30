"""Unified Search API routes."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from deephunter.search.models import (
    SearchQuery,
    SearchResponse,
    SearchScope,
)
from deephunter.search.service import SearchService

router = APIRouter(prefix="/search", tags=["search"])

_search_service = SearchService()


class QueryRequest(BaseModel):
    query: str
    scopes: list[str] = ["all"]
    target_id: str = ""
    investigation_session_id: str = ""
    limit: int = 20
    offset: int = 0
    tags: list[str] = []
    include_archived: bool = False


class SearchResultItem(BaseModel):
    result_type: str
    result_id: str
    title: str
    description: str = ""
    relevance_score: float


class SearchResultsGetResponse(BaseModel):
    query: str
    total_results: int
    results: list[SearchResultItem]
    execution_time_ms: float


class ScopeInfo(BaseModel):
    value: str
    description: str


class SearchScopesResponse(BaseModel):
    scopes: list[ScopeInfo]


@router.post("/", response_model=SearchResponse)
async def search(req: QueryRequest) -> SearchResponse:
    scopes = []
    for s in req.scopes:
        try:
            scopes.append(SearchScope(s))
        except ValueError:
            scopes.append(SearchScope.ALL)

    sq = SearchQuery(
        query=req.query,
        scopes=scopes,
        target_id=req.target_id,
        investigation_session_id=req.investigation_session_id,
        limit=req.limit,
        offset=req.offset,
        tags=req.tags,
        include_archived=req.include_archived,
    )

    results = _search_service.search(sq)
    return results


@router.get("/", response_model=SearchResultsGetResponse)
async def search_get(
    q: str,
    scope: str = "all",
    target_id: str = "",
    limit: int = 20,
    offset: int = 0,
) -> SearchResultsGetResponse:
    scopes = []
    if scope == "all":
        scopes = [SearchScope.ALL]
    else:
        try:
            scopes = [SearchScope(scope)]
        except ValueError:
            scopes = [SearchScope.ALL]

    sq = SearchQuery(
        query=q,
        scopes=scopes,
        target_id=target_id,
        limit=limit,
        offset=offset,
    )

    results = _search_service.search(sq)
    return SearchResultsGetResponse(
        query=results.query,
        total_results=results.total_results,
        results=[
            SearchResultItem(
                result_type=r.result_type.value,
                result_id=r.result_id,
                title=r.title,
                description=r.description,
                relevance_score=r.relevance_score,
            )
            for r in results.results
        ],
        execution_time_ms=results.execution_time_ms,
    )


@router.get("/scopes", response_model=SearchScopesResponse)
async def get_search_scopes() -> SearchScopesResponse:
    return SearchScopesResponse(
        scopes=[
            ScopeInfo(value=s.value, description=_scope_desc(s))
            for s in SearchScope
        ]
    )


def _scope_desc(scope: SearchScope) -> str:
    descriptions = {
        SearchScope.ALL: "Search across all entities",
        SearchScope.NOTEBOOK: "Search notebook entries",
        SearchScope.EVIDENCE: "Search evidence records",
        SearchScope.ENDPOINTS: "Search endpoints",
        SearchScope.PARAMETERS: "Search parameters",
        SearchScope.TECHNOLOGIES: "Search technologies",
        SearchScope.TASKS: "Search tasks",
        SearchScope.FINDINGS: "Search findings",
        SearchScope.HYPOTHESES: "Search hypotheses",
        SearchScope.REPORTS: "Search reports",
        SearchScope.KNOWLEDGE_PACKS: "Search knowledge packs",
        SearchScope.METHODOLOGY_PACKS: "Search methodology packs",
        SearchScope.CONVERSATIONS: "Search AI conversations",
    }
    return descriptions.get(scope, "")
