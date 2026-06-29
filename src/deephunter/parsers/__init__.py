"""Parser engine — document parsing with a common interface."""

from deephunter.parsers.base import (
    Parser,
    ParseResult,
    ParserRegistry,
)
from deephunter.parsers.html_parser import HTMLParser
from deephunter.parsers.json_parser import JSONParser
from deephunter.parsers.markdown_parser import MarkdownParser
from deephunter.parsers.pdf_parser import PDFParser
from deephunter.parsers.yaml_parser import YAMLParser

default_registry = ParserRegistry()
default_registry.register(MarkdownParser())
default_registry.register(HTMLParser())
default_registry.register(JSONParser())
default_registry.register(YAMLParser())
default_registry.register(PDFParser())

__all__ = [
    "ParseResult",
    "Parser",
    "ParserRegistry",
    "default_registry",
    "MarkdownParser",
    "HTMLParser",
    "JSONParser",
    "YAMLParser",
    "PDFParser",
]
