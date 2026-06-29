"""Prompt formatter implementations.

Each formatter converts a Prompt into a specific output format
(Markdown, Plain Text, JSON, Structured XML-like layouts).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from deephunter.prompt.models import Prompt, PromptFormat, PromptMessageRole


class PromptFormatter(ABC):
    """Base class for prompt formatters."""

    @abstractmethod
    def format(self, prompt: Prompt) -> str:
        """Format the prompt into a single output string."""

    @abstractmethod
    def format_messages(self, prompt: Prompt) -> list[dict[str, str]]:
        """Format the prompt into a list of role-content dicts."""


class MarkdownFormatter(PromptFormatter):
    """Format prompts as Markdown with clear role headings."""

    def format(self, prompt: Prompt) -> str:
        parts: list[str] = []
        for msg in prompt.messages:
            header = f"### {msg.role.value.title()} Message"
            if msg.name:
                header += f" ({msg.name})"
            parts.append(f"{header}\n\n{msg.content.strip()}\n")
        return "\n---\n".join(parts)

    def format_messages(self, prompt: Prompt) -> list[dict[str, str]]:
        return [
            {"role": msg.role.value, "content": msg.content}
            for msg in prompt.messages
        ]


class PlainTextFormatter(PromptFormatter):
    """Format prompts as plain text with role prefixes."""

    def format(self, prompt: Prompt) -> str:
        parts: list[str] = []
        for msg in prompt.messages:
            prefix = f"[{msg.role.value.upper()}]"
            if msg.name:
                prefix += f" ({msg.name})"
            parts.append(f"{prefix}\n{msg.content.strip()}")
        return "\n\n".join(parts)

    def format_messages(self, prompt: Prompt) -> list[dict[str, str]]:
        return [
            {"role": msg.role.value, "content": msg.content}
            for msg in prompt.messages
        ]


class JSONFormatter(PromptFormatter):
    """Format prompts as a JSON object."""

    def format(self, prompt: Prompt) -> str:
        data = {
            "prompt_id": prompt.id,
            "context_id": prompt.context_id,
            "investigation_id": prompt.investigation_id,
            "metadata": prompt.metadata.model_dump(mode="json"),
            "messages": self.format_messages(prompt),
            "references": [r.model_dump(mode="json") for r in prompt.references],
            "statistics": prompt.statistics.model_dump(mode="json"),
        }
        return json.dumps(data, indent=2, default=str)

    def format_messages(self, prompt: Prompt) -> list[dict[str, str]]:
        return [
            {"role": msg.role.value, "content": msg.content}
            for msg in prompt.messages
        ]


class StructuredFormatter(PromptFormatter):
    """Format prompts with XML-like structured tags."""

    def format(self, prompt: Prompt) -> str:
        parts: list[str] = ["<prompt>"]
        for msg in prompt.messages:
            attrs = f'role="{msg.role.value}"'
            if msg.name:
                attrs += f' name="{msg.name}"'
            parts.append(f"  <message {attrs}>")
            parts.append(f"    <content>\n{msg.content.strip()}\n    </content>")
            parts.append("  </message>")
        parts.append("</prompt>")
        return "\n".join(parts)

    def format_messages(self, prompt: Prompt) -> list[dict[str, str]]:
        return [
            {"role": msg.role.value, "content": msg.content}
            for msg in prompt.messages
        ]


FORMATTER_MAP: dict[PromptFormat, PromptFormatter] = {
    PromptFormat.MARKDOWN: MarkdownFormatter(),
    PromptFormat.PLAIN_TEXT: PlainTextFormatter(),
    PromptFormat.JSON: JSONFormatter(),
    PromptFormat.STRUCTURED: StructuredFormatter(),
}


def get_formatter(fmt: PromptFormat | str) -> PromptFormatter:
    """Get a formatter by format type.

    Args:
        fmt: A PromptFormat enum value or string name.

    Returns:
        The matching formatter instance.

    Raises:
        ValueError: If the format is unknown.
    """
    if isinstance(fmt, str):
        try:
            fmt = PromptFormat(fmt)
        except ValueError:
            raise ValueError(f"Unknown prompt format: {fmt}") from None
    formatter = FORMATTER_MAP.get(fmt)
    if formatter is None:
        raise ValueError(f"No formatter registered for: {fmt}")
    return formatter
