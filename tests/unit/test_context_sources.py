"""Tests for context source collectors."""

from __future__ import annotations

from deephunter.context.models import (
    Context,
    ContextSourceType,
)
from deephunter.context.sources import (
    collect_from_constraints,
    collect_from_query,
    merge_contexts,
)


class TestCollectFromQuery:
    def test_adds_query_section(self) -> None:
        ctx = Context()
        result = collect_from_query("Test query string", ctx)
        section = result.get_section("User Query")
        assert section is not None
        assert len(section.blocks) == 1
        assert section.blocks[0].content == "Test query string"
        assert section.blocks[0].importance.value == "critical"

    def test_sources_updated(self) -> None:
        ctx = Context()
        result = collect_from_query("Another query", ctx)
        assert any(s.type == ContextSourceType.USER_QUERY for s in result.sources)
        source = [s for s in result.sources if s.type == ContextSourceType.USER_QUERY][0]
        assert source.record_count == 1

    def test_empty_query(self) -> None:
        ctx = Context()
        result = collect_from_query("", ctx)
        section = result.get_section("User Query")
        assert section is not None
        assert section.blocks[0].content == ""


class TestCollectFromConstraints:
    def test_adds_constraints(self) -> None:
        ctx = Context()
        constraints = ["No authentication bypass", "Focus on API endpoints"]
        result = collect_from_constraints(constraints, ctx)
        section = result.get_section("User Constraints")
        assert section is not None
        assert len(section.blocks) == 2
        assert section.blocks[0].content == "No authentication bypass"
        assert section.blocks[1].content == "Focus on API endpoints"

    def test_empty_constraints(self) -> None:
        ctx = Context()
        result = collect_from_constraints([], ctx)
        assert result.get_section("User Constraints") is None

    def test_sources_updated(self) -> None:
        ctx = Context()
        collect_from_constraints(["constraint 1", "constraint 2"], ctx)
        sources = [s for s in ctx.sources if s.type == ContextSourceType.USER_CONSTRAINTS]
        assert len(sources) == 1
        assert sources[0].record_count == 2


class TestMergeContexts:
    def test_merge_empty_list(self) -> None:
        result = merge_contexts([])
        assert isinstance(result, Context)
        assert len(result.sections) == 0

    def test_merge_single(self) -> None:
        ctx = Context(investigation_id="inv-1")
        result = merge_contexts([ctx])
        assert result.investigation_id == "inv-1"

    def test_merge_two_contexts(self) -> None:
        ctx1 = Context()
        ctx2 = Context()

        from deephunter.context.models import ContextSection
        ctx1.add_section(ContextSection(name="Section A"))
        ctx2.add_section(ContextSection(name="Section B"))

        result = merge_contexts([ctx1, ctx2])
        assert len(result.sections) == 2
        assert result.get_section("Section A") is not None
        assert result.get_section("Section B") is not None

    def test_merge_deduplicates_by_section_name(self) -> None:
        ctx1 = Context()
        ctx2 = Context()

        from deephunter.context.models import ContextSection
        ctx1.add_section(ContextSection(name="Same Section"))
        ctx2.add_section(ContextSection(name="Same Section"))

        result = merge_contexts([ctx1, ctx2])
        assert len(result.sections) == 1

    def test_merge_combines_sources(self) -> None:
        from deephunter.context.models import ContextSource

        ctx1 = Context()
        ctx2 = Context()
        ctx1.sources.append(ContextSource(type=ContextSourceType.REASONING_SESSION, name="S1"))
        ctx2.sources.append(ContextSource(type=ContextSourceType.INVESTIGATION_PLAN, name="S2"))

        result = merge_contexts([ctx1, ctx2])
        assert len(result.sources) == 2

    def test_merge_combines_warnings(self) -> None:
        ctx1 = Context()
        ctx2 = Context()
        ctx1.warnings.append("Warning 1")
        ctx2.warnings.append("Warning 2")

        result = merge_contexts([ctx1, ctx2])
        assert "Warning 1" in result.warnings
        assert "Warning 2" in result.warnings
