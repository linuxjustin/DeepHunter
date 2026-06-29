"""Tests for the SKO model."""

from __future__ import annotations

import pytest

from deephunter.core.types import (
    BugClass,
    Confidence,
    DocumentType,
    RelatedReference,
    SourceType,
    Technology,
    TestingIdea,
)
from deephunter.knowledge.models import SecurityKnowledgeObject


class TestSecurityKnowledgeObject:
    def test_create_minimal(self) -> None:
        sko = SecurityKnowledgeObject(
            title="Test Knowledge",
            source="https://test.com",
        )
        assert sko.title == "Test Knowledge"
        assert sko.id.startswith("sko-")
        assert sko.document_type == DocumentType.UNKNOWN

    def test_create_full(self) -> None:
        sko = SecurityKnowledgeObject(
            title="SQLi Techniques",
            summary="SQL injection techniques for MySQL",
            source="https://test.com/sqli",
            source_type=SourceType.PAYLOADS_ALL_THE_THINGS,
            document_type=DocumentType.MARKDOWN,
            tags=["sqli", "mysql"],
            technology=[Technology.NODEJS],
            bug_classes=[BugClass.SQL_INJECTION],
            confidence=Confidence.HIGH,
        )
        assert sko.title == "SQLi Techniques"
        assert BugClass.SQL_INJECTION in sko.bug_classes
        assert Technology.NODEJS in sko.technology

    def test_create_with_references(self) -> None:
        idea = TestingIdea(
            description="Test for JWT none algorithm",
            rationale="JWT libraries often accept 'none'",
        )
        sko = SecurityKnowledgeObject(
            title="JWT Attacks",
            summary="Common JWT attack vectors",
            source="https://test.com/jwt",
            source_type=SourceType.OWASP,
            document_type=DocumentType.MARKDOWN,
            author="test-researcher",
            confidence=Confidence.HIGH,
            tags=["jwt", "authentication"],
            bug_classes=[BugClass.AUTH_BYPASS],
            technology=[Technology.NODEJS],
            references=[RelatedReference(title="OWASP JWT", url="https://owasp.org")],
            high_level_testing_ideas=[idea],
            raw_content="JWT tokens are used for authentication...",
        )
        assert sko.title == "JWT Attacks"
        assert BugClass.AUTH_BYPASS in sko.bug_classes
        assert Technology.NODEJS in sko.technology
        assert sko.confidence == Confidence.HIGH
        assert len(sko.high_level_testing_ideas) == 1
        assert sko.high_level_testing_ideas[0].description == "Test for JWT none algorithm"

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(title="  ", source="test")

    def test_empty_title_rejected(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(title="", source="test")

    def test_model_dump_for_storage(self) -> None:
        sko = SecurityKnowledgeObject(title="Test", source="test")
        data = sko.model_dump_for_storage()
        assert data["title"] == "Test"
        assert data["id"] == sko.id
        assert "created" in data

    def test_from_dict(self) -> None:
        original = SecurityKnowledgeObject(title="Test", source="test")
        data = original.model_dump_for_storage()
        restored = SecurityKnowledgeObject.from_dict(data)
        assert restored.title == "Test"
        assert restored.id == original.id
        assert restored.confidence == Confidence.UNKNOWN

    def test_updated_on_validation(self) -> None:
        sko = SecurityKnowledgeObject(title="Test", source="test")
        assert sko.updated is not None

    def test_direct_construction_with_lists(self) -> None:
        sko = SecurityKnowledgeObject(
            title="Test",
            source="test",
            tags=["a", "b"],
            bug_classes=[BugClass.XSS],
            technology=[Technology.REACT],
        )
        assert len(sko.tags) == 2
        assert len(sko.bug_classes) == 1
        assert len(sko.technology) == 1
