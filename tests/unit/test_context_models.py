"""Tests for context models."""

from __future__ import annotations

import pytest

from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextBudget,
    ContextImportance,
    ContextMetadata,
    ContextReference,
    ContextSection,
    ContextSource,
    ContextSourceType,
    ContextStatistics,
)


class TestContextBlock:
    def test_minimal_creation(self) -> None:
        block = ContextBlock()
        assert block.id.startswith("cb-")
        assert block.source_type == ContextSourceType.OTHER
        assert block.importance == ContextImportance.MEDIUM
        assert block.priority == 0.5
        assert block.content == ""
        assert block.estimated_tokens == 0

    def test_full_creation(self) -> None:
        block = ContextBlock(
            source_type=ContextSourceType.TECHNOLOGY_FINGERPRINT,
            importance=ContextImportance.HIGH,
            priority=0.9,
            content="Test content",
            summary="A test block",
            estimated_tokens=42,
        )
        assert block.source_type == ContextSourceType.TECHNOLOGY_FINGERPRINT
        assert block.importance == ContextImportance.HIGH
        assert block.priority == 0.9
        assert block.content == "Test content"
        assert block.summary == "A test block"
        assert block.estimated_tokens == 42

    def test_serialization_round_trip(self) -> None:
        block = ContextBlock(
            source_type=ContextSourceType.REASONING_SESSION,
            importance=ContextImportance.CRITICAL,
            priority=1.0,
            content="Critical finding content",
            summary="Critical finding",
        )
        data = block.model_dump_for_storage()
        restored = ContextBlock.from_dict(data)
        assert restored.id == block.id
        assert restored.source_type == block.source_type
        assert restored.importance == block.importance
        assert restored.priority == block.priority
        assert restored.content == block.content
        assert restored.summary == block.summary

    def test_dedup_key_default_empty(self) -> None:
        block = ContextBlock()
        assert block.dedup_key == ""

    def test_references_empty_by_default(self) -> None:
        block = ContextBlock()
        assert block.references == []


class TestContextSection:
    def test_minimal_creation(self) -> None:
        section = ContextSection()
        assert section.id.startswith("cs-")
        assert section.blocks == []
        assert section.estimated_tokens == 0

    def test_add_block(self) -> None:
        section = ContextSection(name="Test Section")
        block = ContextBlock(content="test")
        section.add_block(block)
        assert len(section.blocks) == 1
        assert section.blocks[0].section_id == section.id
        assert section.blocks[0].content == "test"

    def test_recalculate(self) -> None:
        section = ContextSection(name="Test")
        block1 = ContextBlock(content="hello world", estimated_tokens=10)
        block2 = ContextBlock(
            content="critical data",
            importance=ContextImportance.CRITICAL,
            priority=0.9,
            estimated_tokens=20,
        )
        section.add_block(block1)
        section.add_block(block2)
        section.recalculate()
        assert section.estimated_tokens == 30
        assert section.importance == ContextImportance.CRITICAL
        assert section.priority == 0.9

    def test_serialization_round_trip(self) -> None:
        section = ContextSection(name="Test", description="A test section")
        section.add_block(ContextBlock(content="block 1"))
        section.add_block(ContextBlock(content="block 2"))
        data = section.model_dump_for_storage()
        restored = ContextSection.from_dict(data)
        assert restored.name == section.name
        assert len(restored.blocks) == 2
        assert restored.id == section.id


class TestContextSource:
    def test_minimal_creation(self) -> None:
        source = ContextSource()
        assert source.type == ContextSourceType.OTHER
        assert source.record_count == 0
        assert source.error is None

    def test_with_values(self) -> None:
        source = ContextSource(
            type=ContextSourceType.REASONING_SESSION,
            name="Test Source",
            record_count=10,
            query_time_ms=5.5,
        )
        assert source.type == ContextSourceType.REASONING_SESSION
        assert source.name == "Test Source"
        assert source.record_count == 10
        assert source.query_time_ms == 5.5


class TestContextReference:
    def test_minimal_creation(self) -> None:
        ref = ContextReference()
        assert ref.reference_type == "other"

    def test_with_values(self) -> None:
        ref = ContextReference(
            reference_type="cve",
            identifier="CVE-2024-1234",
            title="Test CVE",
            url="https://example.com",
        )
        assert ref.reference_type == "cve"
        assert ref.identifier == "CVE-2024-1234"
        assert ref.title == "Test CVE"


class TestContextStatistics:
    def test_defaults(self) -> None:
        stats = ContextStatistics()
        assert stats.total_sections == 0
        assert stats.total_blocks == 0
        assert stats.estimated_tokens == 0
        assert stats.sources_by_type == {}
        assert stats.importance_distribution == {}


class TestContextBudget:
    def test_defaults(self) -> None:
        budget = ContextBudget()
        assert budget.max_tokens == 8192
        assert budget.reserved_system_tokens == 512
        assert budget.reserved_user_tokens == 256
        assert budget.min_important_tokens == 1024
        assert budget.compression_enabled is True

    def test_custom_values(self) -> None:
        budget = ContextBudget(max_tokens=4096, priority_threshold=0.3)
        assert budget.max_tokens == 4096
        assert budget.priority_threshold == 0.3


class TestContextMetadata:
    def test_defaults(self) -> None:
        meta = ContextMetadata()
        assert meta.version == "1"
        assert meta.tags == []

    def test_with_tags(self) -> None:
        meta = ContextMetadata(name="test", tags=["critical", "urgent"])
        assert meta.name == "test"
        assert meta.tags == ["critical", "urgent"]

    def test_extra_fields_allowed(self) -> None:
        meta = ContextMetadata(name="test", source="custom")  # type: ignore[call-arg]
        assert meta.name == "test"
        assert meta.source == "custom"  # type: ignore[attr-defined]


class TestContext:
    def test_minimal_creation(self) -> None:
        ctx = Context()
        assert ctx.id.startswith("ctx-")
        assert ctx.sections == []
        assert ctx.sources == []
        assert ctx.warnings == []

    def test_add_and_get_section(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test Section")
        ctx.add_section(section)
        assert len(ctx.sections) == 1
        assert ctx.get_section("Test Section") is section
        assert ctx.get_section("Nonexistent") is None

    def test_remove_section(self) -> None:
        ctx = Context()
        s1 = ContextSection(name="Keep")
        s2 = ContextSection(name="Remove")
        ctx.add_section(s1)
        ctx.add_section(s2)
        ctx.remove_section(s2.id)
        assert len(ctx.sections) == 1
        assert ctx.sections[0].name == "Keep"

    def test_get_blocks_by_importance(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")
        high = ContextBlock(importance=ContextImportance.HIGH, content="high")
        low = ContextBlock(importance=ContextImportance.LOW, content="low")
        section.add_block(high)
        section.add_block(low)
        ctx.add_section(section)
        highs = ctx.get_blocks_by_importance(ContextImportance.HIGH)
        assert len(highs) == 1
        assert highs[0].content == "high"

    def test_get_blocks_by_source(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")
        b1 = ContextBlock(source_type=ContextSourceType.REASONING_SESSION, content="reasoning")
        b2 = ContextBlock(source_type=ContextSourceType.INVESTIGATION_PLAN, content="plan")
        section.add_block(b1)
        section.add_block(b2)
        ctx.add_section(section)
        results = ctx.get_blocks_by_source(ContextSourceType.REASONING_SESSION)
        assert len(results) == 1
        assert results[0].content == "reasoning"

    def test_get_total_tokens(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(content="a", estimated_tokens=10))
        section.add_block(ContextBlock(content="b", estimated_tokens=20))
        ctx.add_section(section)
        ctx.recalculate()
        assert ctx.get_total_tokens() == 30

    def test_recalculate_statistics(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(
            ContextBlock(
                source_type=ContextSourceType.REASONING_SESSION,
                importance=ContextImportance.HIGH,
                content="test content",
                estimated_tokens=5,
            )
        )
        ctx.add_section(section)
        ctx.recalculate()
        assert ctx.statistics.total_sections == 1
        assert ctx.statistics.total_blocks == 1
        assert ctx.statistics.total_characters == len("test content")
        assert ctx.statistics.estimated_tokens == 5
        assert ctx.statistics.sources_by_type.get("reasoning_session") == 1
        assert ctx.statistics.importance_distribution.get("high") == 1

    def test_serialization_round_trip(self) -> None:
        ctx = Context(investigation_id="inv-test", plan_id="plan-test")
        section = ContextSection(name="Round Trip")
        section.add_block(ContextBlock(content="persist me"))
        ctx.add_section(section)
        ctx.recalculate()

        data = ctx.model_dump_for_storage()
        restored = Context.from_dict(data)
        assert restored.id == ctx.id
        assert restored.investigation_id == ctx.investigation_id
        assert restored.plan_id == ctx.plan_id
        assert len(restored.sections) == 1
        assert restored.sections[0].name == "Round Trip"
        assert restored.sections[0].blocks[0].content == "persist me"

    def test_with_multiple_sections(self) -> None:
        ctx = Context()
        ctx.add_section(ContextSection(name="Section 1"))
        ctx.add_section(ContextSection(name="Section 2"))
        ctx.add_section(ContextSection(name="Section 3"))
        assert len(ctx.sections) == 3

    def test_warnings_append(self) -> None:
        ctx = Context()
        ctx.warnings.append("Warning 1")
        ctx.warnings.append("Warning 2")
        assert len(ctx.warnings) == 2
