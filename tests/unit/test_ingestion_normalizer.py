"""Tests for ContentNormalizer."""

from __future__ import annotations

from deephunter.ingestion.normalizer import ContentNormalizer


class TestContentNormalizer:
    def test_normalize_line_endings(self) -> None:
        raw = "line1\r\nline2\rline3\n"
        result = ContentNormalizer.normalize(raw)
        assert result == "line1\nline2\nline3"

    def test_strip_trailing_whitespace(self) -> None:
        raw = "hello   \nworld\t\n"
        result = ContentNormalizer.normalize(raw)
        assert result == "hello\nworld"

    def test_collapse_excess_blank_lines(self) -> None:
        raw = "a\n\n\n\nb\n\n\nc"
        result = ContentNormalizer.normalize(raw)
        assert result == "a\n\nb\n\nc"

    def test_strip_leading_trailing(self) -> None:
        raw = "  \nhello\n  \n"
        result = ContentNormalizer.normalize(raw)
        assert result == "hello"

    def test_empty_string(self) -> None:
        assert ContentNormalizer.normalize("") == ""

    def test_whitespace_only(self) -> None:
        assert ContentNormalizer.normalize("   \n  \n  ") == ""

    def test_normalize_sko_none(self) -> None:
        assert ContentNormalizer.normalize_sko(None) is None

    def test_normalize_sko_empty(self) -> None:
        assert ContentNormalizer.normalize_sko("") is None

    def test_normalize_sko_whitespace(self) -> None:
        assert ContentNormalizer.normalize_sko("   ") is None

    def test_normalize_sko_valid(self) -> None:
        result = ContentNormalizer.normalize_sko("  hello\nworld  ")
        assert result == "hello\nworld"

    def test_idempotent(self) -> None:
        raw = "  a\n\nb  \n"
        first = ContentNormalizer.normalize(raw)
        second = ContentNormalizer.normalize(first)
        assert first == second
