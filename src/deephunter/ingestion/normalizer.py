"""Content normalization for the ingestion pipeline.

Strips excessive whitespace, normalizes line endings, and produces
a canonical ``normalized_content`` string suitable for deduplication.
"""

from __future__ import annotations

import re

_RE_NEWLINES = re.compile(r"\r\n|\r|\n")
_RE_EXCESS_BLANK_LINES = re.compile(r"\n{3,}")
_RE_LEADING_TRAILING_WS = re.compile(r"^[ \t]+|[ \t]+$", re.MULTILINE)


class ContentNormalizer:
    """Normalizes raw document text.

    Performs deterministic, lossless-enough transformations that
    reduce noise for comparison while preserving meaningful content.
    """

    @staticmethod
    def normalize(raw: str) -> str:
        """Normalize a raw content string.

        Steps:
        1. Normalize line endings (``\\r\\n``, ``\\r`` → ``\\n``).
        2. Strip trailing whitespace from each line.
        3. Collapse 3+ consecutive blank lines to 2.
        4. Strip leading / trailing whitespace from entire string.

        Args:
            raw: The raw content to normalize.

        Returns:
            The normalized content string.
        """
        text = _RE_NEWLINES.sub("\n", raw)
        text = _RE_LEADING_TRAILING_WS.sub("", text)
        text = _RE_EXCESS_BLANK_LINES.sub("\n\n", text)
        return text.strip()

    @classmethod
    def normalize_sko(cls, raw: str | None) -> str | None:
        """Normalize content for storage in an SKO's ``normalized_content`` field.

        Returns ``None`` if ``raw`` is ``None`` or empty after normalization.
        """
        if not raw:
            return None
        result = cls.normalize(raw)
        return result if result else None
