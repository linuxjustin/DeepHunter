"""PDF document parser.

Extracts text from PDF files using PyPDF2. Handles encrypted PDFs
and multi-page documents gracefully.
"""

from __future__ import annotations

from pathlib import Path

from deephunter.core.exceptions import ParsingError
from deephunter.core.types import DocumentType
from deephunter.parsers.base import Parser, ParseResult

try:
    from PyPDF2 import PdfReader

    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False


class PDFParser(Parser):
    """Parser for PDF documents.

    Requires the ``PyPDF2`` library (install with ``deephunter[pdf]``).
    Raises ``ParsingError`` with a helpful message if the dependency
    is missing.
    """

    @property
    def supported_type(self) -> DocumentType:
        return DocumentType.PDF

    def _extensions(self) -> set[str]:
        return {".pdf"}

    def parse(
        self, content: str | bytes, source_path: str | None = None
    ) -> ParseResult:
        if not HAS_PYPDF2:
            raise ParsingError(
                "PyPDF2 is required for PDF parsing. "
                "Install it with: pip install deephunter[pdf]"
            )

        if isinstance(content, str):
            content = content.encode("utf-8")

        if isinstance(content, bytes):
            from io import BytesIO
            content = BytesIO(content)

        try:
            reader = PdfReader(content)
        except Exception as exc:
            raise ParsingError(f"Failed to read PDF: {exc}") from exc

        text_parts: list[str] = []
        sections: dict[str, str] = {}

        for i, page in enumerate(reader.pages):
            try:
                page_text = page.extract_text() or ""
            except Exception as exc:
                raise ParsingError(f"Failed to extract text from page {i}: {exc}") from exc
            text_parts.append(page_text)
            sections[f"page_{i + 1}"] = page_text.strip()

        metadata: dict[str, str] = {}
        source_path_obj = Path(source_path) if source_path else None
        if source_path_obj:
            metadata["filename"] = source_path_obj.name
            metadata["path"] = str(source_path_obj.resolve())
        metadata["pages"] = str(len(reader.pages))

        return ParseResult(
            content="\n".join(text_parts),
            metadata=metadata,
            sections=sections,
        )
