"""JSON document parser.

Handles both single JSON objects and JSON arrays of objects.
Extracts all string values into flat text for downstream processing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from deephunter.core.exceptions import ParsingError
from deephunter.core.types import DocumentType
from deephunter.parsers.base import ParseResult, Parser, ParserRegistry


class JSONParser(Parser):
    """Parser for JSON documents."""

    @property
    def supported_type(self) -> DocumentType:
        return DocumentType.JSON

    def _extensions(self) -> set[str]:
        return {".json"}

    def parse(
        self, content: str | bytes, source_path: Optional[str] = None
    ) -> ParseResult:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        if not content.strip():
            raise ParsingError("Empty JSON content")

        try:
            data: Union[Dict[str, Any], List[Any]] = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParsingError(f"JSON parsing failed: {exc}") from exc

        text = self._flatten(data)
        sections: Dict[str, str] = {}

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (str, int, float, bool)):
                    sections[str(key)] = str(value)
                else:
                    sections[str(key)] = self._flatten(value)

        metadata: Dict[str, str] = {}
        source_path_obj = Path(source_path) if source_path else None
        if source_path_obj:
            metadata["filename"] = source_path_obj.name
            metadata["path"] = str(source_path_obj.resolve())

        if isinstance(data, dict) and "title" in data:
            metadata["title"] = str(data["title"])

        return ParseResult(content=text, metadata=metadata, sections=sections)

    @staticmethod
    def _flatten(data: Any, depth: int = 0) -> str:
        """Recursively flatten a JSON structure into plain text."""
        if depth > 20:
            return ""
        if isinstance(data, str):
            return data
        if isinstance(data, (int, float, bool)):
            return str(data)
        if isinstance(data, list):
            return "\n".join(
                JSONParser._flatten(item, depth + 1) for item in data
            )
        if isinstance(data, dict):
            parts: List[str] = []
            for key, value in data.items():
                flat = JSONParser._flatten(value, depth + 1)
                if flat:
                    parts.append(f"{key}: {flat}")
            return "\n".join(parts)
        return str(data) if data is not None else ""


ParserRegistry.register(JSONParser())