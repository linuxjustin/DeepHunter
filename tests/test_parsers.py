"""Tests for document parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.core.exceptions import ParsingError
from deephunter.core.types import DocumentType
from deephunter.parsers.base import ParseResult, ParserRegistry
from deephunter.parsers.markdown_parser import MarkdownParser
from deephunter.parsers.html_parser import HTMLParser
from deephunter.parsers.json_parser import JSONParser
from deephunter.parsers.yaml_parser import YAMLParser
from deephunter.parsers.pdf_parser import PDFParser

# Re-register parsers for test isolation
@pytest.fixture(autouse=True)
def auto_register():
    ParserRegistry.clear()
    ParserRegistry.register(MarkdownParser())
    ParserRegistry.register(HTMLParser())
    ParserRegistry.register(JSONParser())
    ParserRegistry.register(YAMLParser())
    ParserRegistry.register(PDFParser())
    yield


class TestMarkdownParser:
    def test_parse(self, sample_markdown: str) -> None:
        parser = MarkdownParser()
        result = parser.parse(sample_markdown)
        assert isinstance(result, ParseResult)
        assert "SQL injection" in result.content
        assert result.metadata == {}

    def test_parse_with_path(self, sample_markdown: str) -> None:
        parser = MarkdownParser()
        result = parser.parse(sample_markdown, source_path="/tmp/test.md")
        assert result.metadata["filename"] == "test.md"

    def test_parse_empty(self) -> None:
        parser = MarkdownParser()
        with pytest.raises(ParsingError, match="Empty"):
            parser.parse("")

    def test_parse_bytes(self, sample_markdown: str) -> None:
        parser = MarkdownParser()
        result = parser.parse(sample_markdown.encode("utf-8"))
        assert "SQL injection" in result.content

    def test_supported_type(self) -> None:
        parser = MarkdownParser()
        assert parser.supported_type == DocumentType.MARKDOWN

    def test_can_parse(self) -> None:
        parser = MarkdownParser()
        assert parser.can_parse(Path("test.md"))
        assert parser.can_parse(Path("test.markdown"))
        assert not parser.can_parse(Path("test.html"))


class TestHTMLParser:
    def test_parse(self, sample_html: str) -> None:
        parser = HTMLParser()
        result = parser.parse(sample_html)
        assert isinstance(result, ParseResult)
        assert "Cross-Site Scripting" in result.content
        assert result.metadata.get("title") == "XSS Testing Guide"

    def test_parse_with_path(self, sample_html: str) -> None:
        parser = HTMLParser()
        result = parser.parse(sample_html, source_path="/tmp/test.html")
        assert result.metadata["filename"] == "test.html"

    def test_parse_empty(self) -> None:
        parser = HTMLParser()
        with pytest.raises(ParsingError, match="Empty"):
            parser.parse("")

    def test_supported_type(self) -> None:
        parser = HTMLParser()
        assert parser.supported_type == DocumentType.HTML

    def test_can_parse(self) -> None:
        parser = HTMLParser()
        assert parser.can_parse(Path("test.html"))
        assert parser.can_parse(Path("test.xhtml"))
        assert not parser.can_parse(Path("test.md"))


class TestJSONParser:
    def test_parse_object(self, sample_json: str) -> None:
        parser = JSONParser()
        result = parser.parse(sample_json)
        assert isinstance(result, ParseResult)
        assert "SSRF" in result.content
        assert result.metadata.get("title") == "SSRF Bypass Techniques"

    def test_parse_array(self) -> None:
        parser = JSONParser()
        result = parser.parse('[{"title": "Test A"}, {"title": "Test B"}]')
        assert "Test A" in result.content

    def test_parse_with_path(self, sample_json: str) -> None:
        parser = JSONParser()
        result = parser.parse(sample_json, source_path="/tmp/test.json")
        assert result.metadata["filename"] == "test.json"

    def test_parse_empty(self) -> None:
        parser = JSONParser()
        with pytest.raises(ParsingError, match="Empty"):
            parser.parse("")

    def test_parse_invalid_json(self) -> None:
        parser = JSONParser()
        with pytest.raises(ParsingError, match="JSON parsing failed"):
            parser.parse("{invalid}")

    def test_parse_flat_values(self) -> None:
        parser = JSONParser()
        result = parser.parse('"just a string"')
        assert "just a string" in result.content

    def test_supported_type(self) -> None:
        parser = JSONParser()
        assert parser.supported_type == DocumentType.JSON


class TestYAMLParser:
    def test_parse(self, sample_yaml: str) -> None:
        parser = YAMLParser()
        result = parser.parse(sample_yaml)
        assert isinstance(result, ParseResult)
        assert "Race Condition" in result.content
        assert result.metadata.get("title") == "Race Condition Testing"

    def test_parse_with_path(self, sample_yaml: str) -> None:
        parser = YAMLParser()
        result = parser.parse(sample_yaml, source_path="/tmp/test.yaml")
        assert result.metadata["filename"] == "test.yaml"

    def test_parse_empty(self) -> None:
        parser = YAMLParser()
        with pytest.raises(ParsingError, match="Empty"):
            parser.parse("")

    def test_parse_multi_document(self) -> None:
        parser = YAMLParser()
        yaml_content = "---\na: 1\n---\nb: 2\n"
        result = parser.parse(yaml_content)
        assert "a: 1" in result.content

    def test_supported_type(self) -> None:
        parser = YAMLParser()
        assert parser.supported_type == DocumentType.YAML

    def test_can_parse(self) -> None:
        parser = YAMLParser()
        assert parser.can_parse(Path("test.yaml"))
        assert parser.can_parse(Path("test.yml"))


class TestPDFParser:
    def test_parse_missing_dependency(self) -> None:
        parser = PDFParser()
        # PyPDF2 is installed, but it will fail on fake content
        with pytest.raises(ParsingError):
            parser.parse(b"%PDF-1.4 fake pdf content \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")

    def test_supported_type(self) -> None:
        parser = PDFParser()
        assert parser.supported_type == DocumentType.PDF

    def test_can_parse(self) -> None:
        parser = PDFParser()
        assert parser.can_parse(Path("test.pdf"))
        assert not parser.can_parse(Path("test.md"))


class TestParserRegistry:
    def test_register_and_get(self) -> None:
        parser = ParserRegistry.get(DocumentType.MARKDOWN)
        assert parser is not None
        assert isinstance(parser, MarkdownParser)

        parser = ParserRegistry.get(DocumentType.HTML)
        assert parser is not None
        assert isinstance(parser, HTMLParser)

    def test_get_nonexistent(self) -> None:
        assert ParserRegistry.get(DocumentType.TEXT) is None

    def test_get_for_path(self) -> None:
        parser = ParserRegistry.get_for_path(Path("test.md"))
        assert isinstance(parser, MarkdownParser)

        parser = ParserRegistry.get_for_path(Path("test.html"))
        assert isinstance(parser, HTMLParser)

        parser = ParserRegistry.get_for_path(Path("test.unknown"))
        assert parser is None

    def test_get_for_extension(self) -> None:
        parser = ParserRegistry.get_for_extension("md")
        assert isinstance(parser, MarkdownParser)

        parser = ParserRegistry.get_for_extension(".json")
        assert isinstance(parser, JSONParser)

    def test_list_types(self) -> None:
        types = ParserRegistry.list_types()
        assert DocumentType.MARKDOWN in types
        assert DocumentType.HTML in types
        assert DocumentType.JSON in types
        assert DocumentType.YAML in types
        assert DocumentType.PDF in types

    def test_clear(self) -> None:
        ParserRegistry.clear()
        assert ParserRegistry.list_types() == []
        assert ParserRegistry.get(DocumentType.MARKDOWN) is None