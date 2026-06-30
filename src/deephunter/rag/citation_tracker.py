from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from deephunter.core.types import Metadata as SKOMetadata
from deephunter.knowledge.models import SecurityKnowledgeObject


@dataclass
class Citation:
    id: str = field(default_factory=lambda: f"cit-{uuid4().hex[:12]}")
    source_id: str = ""
    source_title: str = ""
    source_type: str = "sko"
    excerpt: str = ""
    relevance_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CitationGroup:
    query: str = ""
    citations: list[Citation] = field(default_factory=list)
    context: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CitationTracker:
    """Tracks which sources contributed to a RAG response.

    Each query produces a CitationGroup containing all sources
    that influenced the output, along with relevance scores and
    excerpts.
    """

    def __init__(self) -> None:
        self._history: list[CitationGroup] = []
        self._format: str = "markdown"

    def set_format(self, fmt: str) -> None:
        valid = {"markdown", "json", "text"}
        if fmt not in valid:
            raise ValueError(f"Invalid citation format: {fmt}. Valid: {valid}")
        self._format = fmt

    def record(
        self,
        query: str,
        results: list[tuple[SecurityKnowledgeObject, float]],
        context: str = "",
    ) -> CitationGroup:
        citations: list[Citation] = []
        for sko, score in results:
            excerpt = (sko.raw_content or f"{sko.title} {sko.summary}")[:500]
            meta: dict[str, Any] = {"source": sko.source, "tags": sko.tags}
            for m in sko.metadata:
                meta[m.key] = m.value
            citations.append(Citation(
                source_id=sko.id,
                source_title=sko.title,
                source_type="sko",
                excerpt=excerpt,
                relevance_score=round(score, 4),
                metadata=meta,
            ))

        group = CitationGroup(
            query=query,
            citations=citations,
            context=context,
        )
        self._history.append(group)
        return group

    def format_citations(self, group: CitationGroup | None = None) -> str:
        g = group or (self._history[-1] if self._history else None)
        if not g:
            return ""

        if self._format == "json":
            import json
            return json.dumps({
                "query": g.query,
                "citations": [
                    {
                        "id": c.id,
                        "source_id": c.source_id,
                        "source_title": c.source_title,
                        "relevance_score": c.relevance_score,
                        "excerpt": c.excerpt[:200],
                    }
                    for c in g.citations
                ],
            }, indent=2)

        if self._format == "text":
            lines: list[str] = [f"Sources for: {g.query}", ""]
            for i, c in enumerate(g.citations, 1):
                lines.append(f"{i}. {c.source_title} (score: {c.relevance_score})")
                lines.append(f"   ID: {c.source_id}")
                lines.append(f"   Excerpt: {c.excerpt[:150]}...")
                lines.append("")
            return "\n".join(lines)

        lines = [f"## Sources for: {g.query}", ""]
        for i, c in enumerate(g.citations, 1):
            score_pct = int(c.relevance_score * 100)
            lines.append(f"### {i}. {c.source_title} (Relevance: {score_pct}%)")
            lines.append(f"- Source ID: `{c.source_id}`")
            lines.append(f"- Excerpt: {c.excerpt[:200]}...")
            lines.append("")
        return "\n".join(lines)

    def get_history(self, n: int = 5) -> list[CitationGroup]:
        return self._history[-n:]

    def clear(self) -> None:
        self._history.clear()
