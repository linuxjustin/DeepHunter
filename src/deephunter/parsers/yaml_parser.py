"""YAML document parser.

Converts YAML documents to flat text, preserving keys and values.
Handles multi-document YAML streams.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from deephunter.core.exceptions import ParsingError
from deephunter.core.types import DocumentType
from deephunter.parsers.base import Parser, ParseResult


class YAMLParser(Parser):
    """Parser for YAML documents."""

    @property
    def supported_type(self) -> DocumentType:
        return DocumentType.YAML

    def _extensions(self) -> set[str]:
        return {".yaml", ".yml"}

    def parse(
        self, content: str | bytes, source_path: str | None = None
    ) -> ParseResult:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        if not content.strip():
            raise ParsingError("Empty YAML content")

        try:
            documents = list(yaml.safe_load_all(content))
        except yaml.YAMLError as exc:
            raise ParsingError(f"YAML parsing failed: {exc}") from exc

        text_parts: list[str] = []
        sections: dict[str, str] = {}

        for doc in documents:
            if doc is None:
                continue
            if isinstance(doc, dict):
                text_parts.append(self._flatten(doc))
                for key, value in doc.items():
                    if isinstance(value, (str, int, float, bool)):
                        sections[str(key)] = str(value)
                    else:
                        sections[str(key)] = self._flatten(value)
            else:
                text_parts.append(str(doc))

        metadata: dict[str, str] = {}
        source_path_obj = Path(source_path) if source_path else None
        if source_path_obj:
            metadata["filename"] = source_path_obj.name
            metadata["path"] = str(source_path_obj.resolve())

        if documents and isinstance(documents[0], dict) and "title" in documents[0]:
            metadata["title"] = str(documents[0]["title"])

        return ParseResult(
            content="\n".join(text_parts),
            metadata=metadata,
            sections=sections,
        )

    @staticmethod
    def _flatten(data: Any, depth: int = 0) -> str:
        if depth > 20:
            return ""
        if isinstance(data, str):
            return data
        if isinstance(data, (int, float, bool)):
            return str(data)
        if isinstance(data, list):
            return "\n".join(
                YAMLParser._flatten(item, depth + 1) for item in data
            )
        if isinstance(data, dict):
            parts: list[str] = []
            for key, value in data.items():
                flat = YAMLParser._flatten(value, depth + 1)
                if flat:
                    parts.append(f"{key}: {flat}")
            return "\n".join(parts)
        return str(data) if data is not None else ""
