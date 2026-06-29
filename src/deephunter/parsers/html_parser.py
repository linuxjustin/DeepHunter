"""HTML document parser.

Extracts plain text from HTML/XML content using BeautifulSoup.
Strips scripts, styles, and navigation elements while preserving
headings and structured content.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from bs4 import BeautifulSoup

from deephunter.core.exceptions import ParsingError
from deephunter.core.types import DocumentType
from deephunter.parsers.base import ParseResult, Parser, ParserRegistry


class HTMLParser(Parser):
    """Parser for HTML/XML documents."""

    @property
    def supported_type(self) -> DocumentType:
        return DocumentType.HTML

    def _extensions(self) -> set[str]:
        return {".html", ".htm", ".xhtml", ".xml"}

    def parse(
        self, content: str | bytes, source_path: Optional[str] = None
    ) -> ParseResult:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        if not content.strip():
            raise ParsingError("Empty HTML content")

        try:
            soup = BeautifulSoup(content, "lxml")
        except Exception as exc:
            raise ParsingError(f"HTML parsing failed: {exc}") from exc

        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)

        sections: dict[str, str] = {}
        for heading in soup.find_all(["h1", "h2", "h3"]):
            section_text = heading.get_text(strip=True)
            siblings: list[str] = []
            for sibling in heading.find_next_siblings():
                if sibling.name and sibling.name.startswith("h"):
                    break
                siblings.append(sibling.get_text(strip=True))
            sections[section_text] = "\n".join(siblings)

        metadata: dict[str, str] = {}
        source_path_obj = Path(source_path) if source_path else None
        if source_path_obj:
            metadata["filename"] = source_path_obj.name
            metadata["path"] = str(source_path_obj.resolve())

        title_tag = soup.find("title")
        if title_tag:
            metadata["title"] = title_tag.get_text(strip=True)

        return ParseResult(content=text, metadata=metadata, sections=sections)


ParserRegistry.register(HTMLParser())