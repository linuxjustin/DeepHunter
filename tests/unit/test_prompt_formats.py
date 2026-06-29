"""Tests for prompt formatters."""

from __future__ import annotations

import json

import pytest

from deephunter.prompt.formats import (
    JSONFormatter,
    MarkdownFormatter,
    PlainTextFormatter,
    StructuredFormatter,
    get_formatter,
)
from deephunter.prompt.models import (
    Prompt,
    PromptFormat,
    PromptMessageRole,
    PromptStyle,
)


class TestMarkdownFormatter:
    def test_format(self) -> None:
        formatter = MarkdownFormatter()
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "System instruction")
        prompt.add_message(PromptMessageRole.USER, "User query")

        output = formatter.format(prompt)
        assert "### System Message" in output
        assert "### User Message" in output
        assert "System instruction" in output
        assert "User query" in output

    def test_format_messages(self) -> None:
        formatter = MarkdownFormatter()
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "S", name="main")
        prompt.add_message(PromptMessageRole.USER, "U")

        msgs = formatter.format_messages(prompt)
        assert len(msgs) == 2
        assert msgs[0] == {"role": "system", "content": "S"}
        assert msgs[1] == {"role": "user", "content": "U"}


class TestPlainTextFormatter:
    def test_format(self) -> None:
        formatter = PlainTextFormatter()
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "S")
        prompt.add_message(PromptMessageRole.USER, "U")

        output = formatter.format(prompt)
        assert "[SYSTEM]" in output
        assert "[USER]" in output
        assert "S" in output
        assert "U" in output

    def test_format_messages(self) -> None:
        formatter = PlainTextFormatter()
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "S")

        msgs = formatter.format_messages(prompt)
        assert msgs[0] == {"role": "system", "content": "S"}


class TestJSONFormatter:
    def test_format(self) -> None:
        formatter = JSONFormatter()
        prompt = Prompt(investigation_id="inv-1")
        prompt.metadata.style = PromptStyle.REASONING
        prompt.add_message(PromptMessageRole.SYSTEM, "S")

        output = formatter.format(prompt)
        data = json.loads(output)
        assert data["investigation_id"] == "inv-1"
        assert data["metadata"]["style"] == "reasoning"
        assert len(data["messages"]) == 1
        assert data["messages"][0] == {"role": "system", "content": "S"}

    def test_format_messages(self) -> None:
        formatter = JSONFormatter()
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.USER, "hello")

        msgs = formatter.format_messages(prompt)
        assert msgs == [{"role": "user", "content": "hello"}]


class TestStructuredFormatter:
    def test_format(self) -> None:
        formatter = StructuredFormatter()
        prompt = Prompt()
        prompt.add_message(PromptMessageRole.SYSTEM, "Be helpful")
        prompt.add_message(PromptMessageRole.USER, "Hi", name="main")

        output = formatter.format(prompt)
        assert "<prompt>" in output
        assert "</prompt>" in output
        assert 'role="system"' in output
        assert 'role="user"' in output
        assert 'name="main"' in output
        assert "Be helpful" in output


class TestGetFormatter:
    def test_by_enum(self) -> None:
        formatter = get_formatter(PromptFormat.MARKDOWN)
        assert isinstance(formatter, MarkdownFormatter)

    def test_by_string(self) -> None:
        formatter = get_formatter("json")
        assert isinstance(formatter, JSONFormatter)

    def test_by_string_plain_text(self) -> None:
        formatter = get_formatter("plain_text")
        assert isinstance(formatter, PlainTextFormatter)

    def test_by_string_structured(self) -> None:
        formatter = get_formatter("structured")
        assert isinstance(formatter, StructuredFormatter)

    def test_unknown_format(self) -> None:
        with pytest.raises(ValueError, match="Unknown prompt format"):
            get_formatter("unknown_format")
