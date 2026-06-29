"""Tests for core type definitions."""

from __future__ import annotations

from deephunter.core.types import (
    AuthMechanism,
    BugClass,
    CloudProvider,
    Confidence,
    DocumentType,
    Framework,
    Metadata,
    RelatedReference,
    SourceType,
    Technology,
    TestingIdea,
    TrustBoundary,
)


class TestEnums:
    def test_document_type_values(self) -> None:
        assert DocumentType.MARKDOWN.value == "markdown"
        assert DocumentType.PDF.value == "pdf"
        assert DocumentType.UNKNOWN.value == "unknown"

    def test_source_type_values(self) -> None:
        assert SourceType.OWASP.value == "owasp"
        assert SourceType.HACKTRICKS.value == "hacktricks"
        assert SourceType.CVE.value == "cve"

    def test_bug_class_values(self) -> None:
        assert BugClass.XSS.value == "xss"
        assert BugClass.SQL_INJECTION.value == "sql_injection"
        assert BugClass.SSRF.value == "ssrf"

    def test_confidence_values(self) -> None:
        assert Confidence.HIGH.value == "high"
        assert Confidence.LOW.value == "low"

    def test_technology_values(self) -> None:
        assert Technology.NODEJS.value == "nodejs"
        assert Technology.DJANGO.value == "django"

    def test_cloud_provider_values(self) -> None:
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.GCP.value == "gcp"

    def test_auth_mechanism_values(self) -> None:
        assert AuthMechanism.JWT.value == "jwt"
        assert AuthMechanism.OAUTH2.value == "oauth2"

    def test_framework_values(self) -> None:
        assert Framework.OWASP_WSTG.value == "owasp_wstg"


class TestTrustBoundary:
    def test_create(self) -> None:
        tb = TrustBoundary(
            name="API Gateway",
            description="Between internet and internal services",
            direction="external->internal",
        )
        assert tb.name == "API Gateway"
        assert tb.sensitivity == "medium"

    def test_high_sensitivity(self) -> None:
        tb = TrustBoundary(
            name="Database",
            description="Between app and database",
            direction="app->db",
            sensitivity="high",
        )
        assert tb.sensitivity == "high"


class TestTestingIdea:
    def test_create(self) -> None:
        idea = TestingIdea(
            description="Test for JWT alg confusion",
            rationale="Many libraries default to 'none' algorithm",
            bug_classes=[BugClass.AUTH_BYPASS],
        )
        assert idea.difficulty == "medium"
        assert BugClass.AUTH_BYPASS in idea.bug_classes

    def test_with_references(self) -> None:
        idea = TestingIdea(
            description="Test SQL injection",
            rationale="User input is reflected in queries",
            references=["https://example.com/sqli"],
        )
        assert len(idea.references) == 1


class TestRelatedReference:
    def test_create(self) -> None:
        ref = RelatedReference(title="OWASP Top 10", url="https://owasp.org")
        assert ref.title == "OWASP Top 10"
        assert ref.description is None

    def test_full(self) -> None:
        ref = RelatedReference(
            title="Test",
            url="https://test.com",
            source="test",
            description="A test reference",
        )
        assert ref.description == "A test reference"


class TestMetadata:
    def test_create(self) -> None:
        m = Metadata(key="author", value="test_user")
        assert m.key == "author"
        assert m.value == "test_user"

    def test_with_tags(self) -> None:
        m = Metadata(key="source", value="portswigger", tags=["xss", "sqli"])
        assert len(m.tags) == 2
