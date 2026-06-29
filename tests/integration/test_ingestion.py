"""Tests for the ingestion pipeline and metadata extractor."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.core.types import BugClass, CloudProvider, SourceType, Technology
from deephunter.ingestion.extractor import MetadataExtractor
from deephunter.ingestion.extractor import MetadataExtractor
from deephunter.ingestion.pipeline import IngestionPipeline
from deephunter.knowledge.store import KnowledgeStore
from deephunter.parsers.base import ParserRegistry
from deephunter.parsers.html_parser import HTMLParser
from deephunter.parsers.markdown_parser import MarkdownParser


@pytest.fixture
def parser_registry() -> ParserRegistry:
    reg = ParserRegistry()
    reg.register(MarkdownParser())
    reg.register(HTMLParser())
    return reg


class TestMetadataExtractor:
    def test_extract_technologies(self) -> None:
        text = "The application uses React and Node.js with Express."
        techs = MetadataExtractor.extract_technologies(text)
        assert Technology.REACT in techs
        assert Technology.NODEJS in techs
        assert Technology.EXPRESS in techs

    def test_extract_technologies_empty(self) -> None:
        techs = MetadataExtractor.extract_technologies("No technologies mentioned.")
        assert techs == []

    def test_extract_bug_classes(self) -> None:
        text = "SQL injection and XSS are common. Also test for SSRF."
        bugs = MetadataExtractor.extract_bug_classes(text)
        assert BugClass.SQL_INJECTION in bugs
        assert BugClass.XSS in bugs
        assert BugClass.SSRF in bugs

    def test_extract_bug_classes_empty(self) -> None:
        bugs = MetadataExtractor.extract_bug_classes("No vulnerabilities here.")
        assert bugs == []

    def test_extract_bug_classes_multiple_matches(self) -> None:
        text = "xss vulnerability and cross-site scripting"
        bugs = MetadataExtractor.extract_bug_classes(text)
        assert BugClass.XSS in bugs
        assert len(bugs) == 1

    def test_extract_cloud_providers(self) -> None:
        text = "Deployed on AWS using S3 and Lambda."
        clouds = MetadataExtractor.extract_cloud_providers(text)
        assert CloudProvider.AWS in clouds

    def test_extract_cloud_providers_empty(self) -> None:
        clouds = MetadataExtractor.extract_cloud_providers("On-premise only.")
        assert clouds == []

    def test_extract_all(self) -> None:
        text = "Node.js app on AWS has SQL injection and XSS."
        result = MetadataExtractor.extract_all(text)
        assert "technologies" in result
        assert "bug_classes" in result
        assert "cloud_providers" in result


class TestIngestionPipeline:
    def test_detect_source_type(self, sample_config, parser_registry) -> None:
        pipeline = IngestionPipeline(sample_config, KnowledgeStore(), parser_registry=parser_registry)
        assert pipeline._detect_source_type(Path("knowledge/hacktricks/xss.md")) == SourceType.HACKTRICKS
        assert pipeline._detect_source_type(Path("knowledge/writeups/bug.md")) == SourceType.WRITEUP
        assert pipeline._detect_source_type(Path("knowledge/cves/CVE-2024-123.md")) == SourceType.CVE
        assert pipeline._detect_source_type(Path("knowledge/notes/my_note.md")) == SourceType.INTERNAL_NOTES
        assert pipeline._detect_source_type(Path("some/other/file.md")) == SourceType.OTHER

    def test_detect_document_type(self, sample_config, parser_registry) -> None:
        pipeline = IngestionPipeline(sample_config, KnowledgeStore(), parser_registry=parser_registry)
        for ext in [".md", ".html", ".json", ".yaml", ".pdf", ".txt"]:
            dt = pipeline._detect_document_type(Path(f"/tmp/test{ext}"))
            assert dt is not None

    def test_parse_single_markdown(self, sample_config, sample_markdown: str, tmp_path, parser_registry) -> None:
        file_path = tmp_path / "sqli.md"
        file_path.write_text(sample_markdown)

        pipeline = IngestionPipeline(sample_config, KnowledgeStore(), parser_registry=parser_registry)
        sko = pipeline.parse_single(str(file_path))

        assert sko.title == "SQL Injection Testing"
        assert "SQL injection" in sko.summary
        assert BugClass.SQL_INJECTION in sko.bug_classes

    def test_parse_single_file_not_found(self, sample_config, parser_registry) -> None:
        pipeline = IngestionPipeline(sample_config, KnowledgeStore(), parser_registry=parser_registry)
        with pytest.raises(FileNotFoundError):
            pipeline.parse_single("/nonexistent/file.md")

    def test_parse_single_no_parser(self, sample_config, tmp_path, parser_registry) -> None:
        file_path = tmp_path / "test.xyz"
        file_path.write_text("content")

        pipeline = IngestionPipeline(sample_config, KnowledgeStore(), parser_registry=parser_registry)
        with pytest.raises(Exception):
            pipeline.parse_single(str(file_path))

    def test_run_empty_config(self, sample_config, parser_registry) -> None:
        store = KnowledgeStore()
        pipeline = IngestionPipeline(sample_config, store, parser_registry=parser_registry)
        # Add a watch directory that doesn't exist
        sample_config.ingestion.watch_directories = ["/nonexistent"]
        report = pipeline.run()
        assert report.total == 0
        assert report.stored == 0
