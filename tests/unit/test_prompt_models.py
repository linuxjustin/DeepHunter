"""Tests for prompt models."""

from __future__ import annotations

import pytest

from deephunter.prompt.models import (
    Prompt,
    PromptFormat,
    PromptMessage,
    PromptMessageRole,
    PromptMetadata,
    PromptReference,
    PromptStatistics,
    PromptStyle,
    PromptTemplate,
)


class TestPromptMessage:
    def test_minimal_creation(self) -> None:
        msg = PromptMessage(role=PromptMessageRole.USER, content="Hello")
        assert msg.role == PromptMessageRole.USER
        assert msg.content == "Hello"
        assert msg.name == ""

    def test_with_name(self) -> None:
        msg = PromptMessage(role=PromptMessageRole.SYSTEM, content="Be helpful", name="system1")
        assert msg.name == "system1"


class TestPromptTemplate:
    def test_minimal_creation(self) -> None:
        tpl = PromptTemplate(id="test", name="Test")
        assert tpl.id == "test"
        assert tpl.style == PromptStyle.INVESTIGATION

    def test_with_style(self) -> None:
        tpl = PromptTemplate(
            id="reason",
            name="Reasoning",
            style=PromptStyle.REASONING,
            system_template="You are a reasoning engine.",
            variables=["context_summary"],
        )
        assert tpl.style == PromptStyle.REASONING
        assert "context_summary" in tpl.variables


class TestPromptMetadata:
    def test_defaults(self) -> None:
        meta = PromptMetadata()
        assert meta.style == PromptStyle.INVESTIGATION
        assert meta.format == "markdown"
        assert meta.model_adapter == ""

    def test_extra_fields_allowed(self) -> None:
        meta = PromptMetadata(style=PromptStyle.REASONING, custom="value")  # type: ignore[call-arg]
        assert meta.custom == "value"  # type: ignore[attr-defined]


class TestPromptStatistics:
    def test_defaults(self) -> None:
        stats = PromptStatistics()
        assert stats.total_messages == 0
        assert stats.total_characters == 0
        assert stats.estimated_tokens == 0
        assert stats.characters_by_role == {}


class TestPromptReference:
    def test_minimal(self) -> None:
        ref = PromptReference()
        assert ref.reference_type == "other"

    def test_with_values(self) -> None:
        ref = PromptReference(
            reference_type="cve",
            identifier="CVE-2024-5678",
            title="Example CVE",
        )
        assert ref.identifier == "CVE-2024-5678"


class TestPrompt:
    def test_minimal_creation(self) -> None:
        prompt = Prompt()
        assert prompt.id.startswith("prompt-")
        assert prompt.messages == []
        assert prompt.warnings == []

    def test_add_message(self) -> None:
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "System instruction")
        prompt.add_message(PromptMessageRole.USER, "User query")
        assert len(prompt.messages) == 2
        assert prompt.messages[0].role == PromptMessageRole.SYSTEM
        assert prompt.messages[1].role == PromptMessageRole.USER

    def test_add_message_with_name(self) -> None:
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.TOOL, "Tool output", name="scanner")
        assert prompt.messages[0].name == "scanner"

    def test_to_system_user_system_and_user(self) -> None:
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "System message")
        prompt.add_message(PromptMessageRole.USER, "User message")
        system, user = prompt.to_system_user()
        assert system == "System message"
        assert user == "User message"

    def test_to_system_user_only_user(self) -> None:
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.USER, "Only user message")
        system, user = prompt.to_system_user()
        assert system == ""
        assert user == "Only user message"

    def test_to_system_user_multiple_messages(self) -> None:
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.USER, "First")
        prompt.add_message(PromptMessageRole.SYSTEM, "System")
        prompt.add_message(PromptMessageRole.USER, "Second")
        system, user = prompt.to_system_user()
        # First system and first user
        assert system == "System"
        assert user == "First"

    def test_recalculate(self) -> None:
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "System instruction")
        prompt.add_message(PromptMessageRole.USER, "User query text here")
        prompt.recalculate()
        assert prompt.statistics.total_messages == 2
        assert prompt.statistics.total_characters > 0
        assert prompt.statistics.estimated_tokens > 0
        assert "system" in prompt.statistics.characters_by_role
        assert "user" in prompt.statistics.characters_by_role

    def test_serialization_round_trip(self) -> None:
        prompt = Prompt(investigation_id="inv-test")
        prompt.add_message(PromptMessageRole.SYSTEM, "System")
        prompt.add_message(PromptMessageRole.USER, "User")
        prompt.recalculate()

        data = prompt.model_dump_for_storage()
        restored = Prompt.from_dict(data)
        assert restored.id == prompt.id
        assert restored.investigation_id == prompt.investigation_id
        assert len(restored.messages) == 2
        assert restored.messages[0].content == "System"
        assert restored.messages[1].content == "User"

    def test_references_list(self) -> None:
        prompt = Prompt()
        prompt.references.append(PromptReference(reference_type="cve", identifier="CVE-2024-0001"))
        assert len(prompt.references) == 1
