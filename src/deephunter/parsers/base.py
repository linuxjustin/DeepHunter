"""Base parser interface and registry.

All document parsers implement the ``Parser`` protocol and register
themselves with the global ``ParserRegistry``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from deephunter.core.types import DocumentType


@dataclass
class ParseResult:
    """The result of parsing a single document.

    The ``content`` field contains the extracted plain text.
    ``metadata`` holds document-level metadata such as title, author,
    or creation date discovered during parsing.
    """

    content: str
    metadata: dict[str, str] = field(default_factory=dict)
    sections: dict[str, str] = field(default_factory=dict)


class Parser(ABC):
    """Abstract base for all document parsers.

    Each parser implementation handles one ``DocumentType`` and
    produces a ``ParseResult`` with extracted text and metadata.
    """

    @property
    @abstractmethod
    def supported_type(self) -> DocumentType:
        """The document type this parser can handle."""

    @abstractmethod
    def parse(self, content: str | bytes, source_path: str | None = None) -> ParseResult:
        """Parse document content into structured text.

        Args:
            content: The raw document content (string or bytes).
            source_path: Optional original file path for context.

        Returns:
            A ParseResult with extracted text and metadata.

        Raises:
            ParsingError: If the content cannot be parsed.
        """

    def can_parse(self, path: Path) -> bool:
        """Check if this parser can handle a given file path.

        The default implementation checks the file extension.
        Subclasses may override for content-based detection.
        """
        return self._extensions().intersection(
            {path.suffix.lower(), f".{path.suffix.lower()}"}
        ).__len__() > 0

    def _extensions(self) -> set[str]:
        """Return the set of file extensions this parser handles."""
        return set()


class ParserRegistry:
    """Registry mapping document types to parser implementations."""

    def __init__(self) -> None:
        self._parsers: dict[DocumentType, Parser] = {}

    def register(self, parser: Parser) -> None:
        """Register a parser instance.

        Args:
            parser: A parser instance.

        Raises:
            ValueError: If a parser for the same type is already registered.
        """
        dt = parser.supported_type
        if dt in self._parsers:
            raise ValueError(f"Parser for {dt} already registered: {type(self._parsers[dt]).__name__}")
        self._parsers[dt] = parser

    def get(self, document_type: DocumentType) -> Parser | None:
        """Get the registered parser for a document type.

        Args:
            document_type: The target document type.

        Returns:
            The parser, or ``None`` if none is registered.
        """
        return self._parsers.get(document_type)

    def get_for_path(self, path: Path) -> Parser | None:
        """Find a parser that can handle the given file path.

        Args:
            path: The file path to check.

        Returns:
            The first matching parser, or ``None``.
        """
        for parser in self._parsers.values():
            if parser.can_parse(path):
                return parser
        return None

    def get_for_extension(self, ext: str) -> Parser | None:
        """Find a parser for the given file extension.

        Args:
            ext: File extension with or without leading dot (e.g. 'md', '.md').

        Returns:
            The matching parser, or ``None``.
        """
        return self.get_for_path(Path(f"file.{ext.lstrip('.')}"))

    def list_types(self) -> list[DocumentType]:
        """List all registered document types."""
        return list(self._parsers.keys())

    def clear(self) -> None:
        """Clear all registered parsers (primarily for testing)."""
        self._parsers.clear()
