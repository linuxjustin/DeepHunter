"""Parser engine — document parsing with a common interface."""

from deephunter.parsers.base import (
    ParseResult,
    Parser,
    ParserRegistry,
)
from deephunter.parsers.markdown_parser import MarkdownParser
from deephunter.parsers.html_parser import HTMLParser
from deephunter.parsers.json_parser import JSONParser
from deephunter.parsers.yaml_parser import YAMLParser
from deephunter.parsers.pdf_parser import PDFParser

__all__ = [
    "ParseResult",
    "Parser",
    "ParserRegistry",
    "MarkdownParser",
    "HTMLParser",
    "JSONParser",
    "YAMLParser",
    "PDFParser",
]