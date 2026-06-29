"""Markdown document parser.

Extracts plain text from Markdown content. Handles code blocks,
headings, lists, and basic formatting. Uses Python's ``markdown``
library to convert to HTML, then ``BeautifulSoup`` for text extraction.
"""

from __future__ import annotations

from pathlib import Path

import markdown
from bs4 import BeautifulSoup

from deephunter.core.exceptions import ParsingError
from deephunter.core.types import DocumentType
from deephunter.parsers.base import Parser, ParseResult


class MarkdownParser(Parser):
    """Parser for Markdown documents."""

    @property
    def supported_type(self) -> DocumentType:
        return DocumentType.MARKDOWN

    def _extensions(self) -> set[str]:
        return {".md", ".markdown", ".mdown"}

    def parse(
        self, content: str | bytes, source_path: str | None = None
    ) -> ParseResult:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        if not content.strip():
            raise ParsingError("Empty Markdown content")

        try:
            html = markdown.markdown(
                content,
                extensions=["fenced_code", "codehilite", "tables", "nl2br"],
            )
        except Exception as exc:
            raise ParsingError(f"Markdown conversion failed: {exc}") from exc

        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(separator="\n", strip=True)

        sections: dict[str, str] = {}
        current_heading = "intro"
        current_lines: list[str] = []

        for line in content.split("\n"):
            if line.startswith("#"):
                if current_lines:
                    sections[current_heading] = "\n".join(current_lines).strip()
                current_heading = line.lstrip("#").strip()
                current_lines = []
            else:
                current_lines.append(line)
        if current_lines:
            sections[current_heading] = "\n".join(current_lines).strip()

        metadata: dict[str, str] = {}
        source_path_obj = Path(source_path) if source_path else None
        if source_path_obj:
            metadata["filename"] = source_path_obj.name
            metadata["path"] = str(source_path_obj.resolve())

        return ParseResult(content=text, metadata=metadata, sections=sections)
