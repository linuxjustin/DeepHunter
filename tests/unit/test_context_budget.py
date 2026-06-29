"""Tests for context token budget management."""

from __future__ import annotations

from deephunter.context.budget import apply_budget, estimate_tokens
from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextBudget,
    ContextImportance,
    ContextSection,
    ContextSourceType,
)


class TestEstimateTokens:
    def test_word_count_method(self) -> None:
        tokens = estimate_tokens("hello world", method="word_count")
        # 2 words / 0.75 = 2.67 -> int truncates to 2
        assert tokens == 2

    def test_word_count_empty(self) -> None:
        tokens = estimate_tokens("", method="word_count")
        assert tokens == 1

    def test_character_count_method(self) -> None:
        tokens = estimate_tokens("abc", method="character_count")
        assert tokens == 1  # 3 chars / 4 = 0.75 -> max 1 = 1

    def test_character_count_long(self) -> None:
        tokens = estimate_tokens("a" * 20, method="character_count")
        assert tokens == 5  # 20 / 4 = 5


class TestApplyBudget:
    def test_no_budget_needed(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(content="small content"))
        ctx.add_section(section)
        ctx.recalculate()

        result = apply_budget(ctx)
        assert len(result.sections[0].blocks) == 1

    def test_budget_trims_low_priority(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")

        section.add_block(ContextBlock(
            content="critical data",
            importance=ContextImportance.CRITICAL,
            priority=1.0,
        ))
        section.add_block(ContextBlock(
            content="low priority " * 10,
            importance=ContextImportance.LOW,
            priority=0.1,
        ))
        ctx.add_section(section)
        ctx.recalculate()

        # Small budget with zero reserved to leave room for blocks
        budget = ContextBudget(
            max_tokens=10,
            reserved_system_tokens=0,
            reserved_user_tokens=0,
        )
        result = apply_budget(ctx, budget)

        # Low priority block should be removed first, critical protected
        assert len(result.sections[0].blocks) == 1
        assert result.sections[0].blocks[0].importance == ContextImportance.CRITICAL

    def test_budget_keeps_important_blocks(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")

        section.add_block(ContextBlock(
            content="critical data",
            importance=ContextImportance.CRITICAL,
            priority=1.0,
            estimated_tokens=50,
        ))
        section.add_block(ContextBlock(
            content="high data",
            importance=ContextImportance.HIGH,
            priority=0.9,
            estimated_tokens=50,
        ))
        ctx.add_section(section)
        ctx.recalculate()

        budget = ContextBudget(
            max_tokens=200,
            reserved_system_tokens=20,
            reserved_user_tokens=10,
        )
        result = apply_budget(ctx, budget)

        # Both blocks should fit
        assert len(result.sections[0].blocks) == 2

    def test_no_sections(self) -> None:
        ctx = Context()
        result = apply_budget(ctx)
        assert len(result.sections) == 0

    def test_budget_fully_reserved(self) -> None:
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(content="data"))
        ctx.add_section(section)

        budget = ContextBudget(
            max_tokens=100,
            reserved_system_tokens=100,
            reserved_user_tokens=0,
        )
        result = apply_budget(ctx, budget)
        assert "fully reserved" in result.warnings[0]
