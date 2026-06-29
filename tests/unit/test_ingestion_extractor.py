"""Tests for the enhanced MetadataExtractor (frameworks, languages, OS, author, title, tags)."""

from __future__ import annotations

from deephunter.core.types import CloudProvider, Framework, Technology
from deephunter.ingestion.extractor import MetadataExtractor


class TestMetadataExtractorFrameworks:
    def test_extract_frameworks(self) -> None:
        text = "This follows the OWASP ASVS standard and maps to MITRE ATT&CK."
        fws = MetadataExtractor.extract_frameworks(text)
        assert Framework.OWASP_ASVS in fws
        assert Framework.MITRE_ATTACK in fws

    def test_extract_frameworks_empty(self) -> None:
        assert MetadataExtractor.extract_frameworks("No frameworks here.") == []


class TestMetadataExtractorLanguages:
    def test_extract_languages_python(self) -> None:
        text = "The app uses Python with Django and Flask."
        langs = MetadataExtractor.extract_programming_languages(text)
        assert "Python" in langs

    def test_extract_languages_go(self) -> None:
        text = "Written in Golang with Gin gonic."
        langs = MetadataExtractor.extract_programming_languages(text)
        assert "Go" in langs

    def test_extract_languages_javascript(self) -> None:
        text = "Uses Node.js for backend and Express."
        langs = MetadataExtractor.extract_programming_languages(text)
        assert "JavaScript" in langs

    def test_extract_languages_empty(self) -> None:
        assert MetadataExtractor.extract_programming_languages("No code here.") == []


class TestMetadataExtractorOS:
    def test_extract_os_linux(self) -> None:
        text = "Deployed on Ubuntu Linux servers."
        oss = MetadataExtractor.extract_operating_systems(text)
        assert "Linux" in oss

    def test_extract_os_windows(self) -> None:
        text = "Active Directory on Windows Server."
        oss = MetadataExtractor.extract_operating_systems(text)
        assert "Windows" in oss

    def test_extract_os_empty(self) -> None:
        assert MetadataExtractor.extract_operating_systems("No OS mentioned.") == []


class TestMetadataExtractorTitle:
    def test_extract_title_from_h1(self) -> None:
        text = "# SQL Injection Testing\n\nSome content"
        assert MetadataExtractor.extract_title(text) == "SQL Injection Testing"

    def test_extract_title_from_html(self) -> None:
        text = "<html><title>XSS Guide</title><body>Content</body></html>"
        assert MetadataExtractor.extract_title(text) == "XSS Guide"

    def test_extract_title_from_first_line(self) -> None:
        text = "First Line Is Title\n\nContent follows"
        assert MetadataExtractor.extract_title(text) == "First Line Is Title"

    def test_extract_title_empty(self) -> None:
        assert MetadataExtractor.extract_title("") is None


class TestMetadataExtractorAuthor:
    def test_extract_author_md(self) -> None:
        text = "Author: John Doe\nContent here"
        assert MetadataExtractor.extract_author(text) == "John Doe"

    def test_extract_author_by(self) -> None:
        text = "By: Jane Smith\nContent"
        assert MetadataExtractor.extract_author(text) == "Jane Smith"

    def test_extract_author_none(self) -> None:
        assert MetadataExtractor.extract_author("No author here") is None


class TestMetadataExtractorTags:
    def test_extract_tags(self) -> None:
        text = "Uses JWT and OAuth for authentication."
        tags = MetadataExtractor.extract_tags(text)
        assert "authentication" in tags

    def test_extract_tags_api(self) -> None:
        text = "REST API with API key authentication."
        tags = MetadataExtractor.extract_tags(text)
        assert "api-security" in tags

    def test_extract_tags_empty(self) -> None:
        assert MetadataExtractor.extract_tags("Nothing relevant here.") == []


class TestMetadataExtractorExtractAll:
    def test_extract_all(self) -> None:
        text = "Node.js app on AWS with SQL injection and XSS."
        result = MetadataExtractor.extract_all(text)
        assert "technologies" in result
        assert "bug_classes" in result
        assert "cloud_providers" in result
        assert "frameworks" in result
        assert "languages" in result
        assert "operating_systems" in result
        assert "tags" in result
