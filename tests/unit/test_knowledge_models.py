"""Tests for the SKO model."""

from __future__ import annotations

import pytest

from deephunter.core.types import (
    AttackSurfaceEntry,
    AuthorizationModel,
    BugClass,
    BusinessLogicConcern,
    Confidence,
    DocumentType,
    ManualTestChecklistItem,
    PayloadReference,
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
        assert sko.schema_version == 1

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
            SecurityKnowledgeObject(title="  ", source="https://test.com")

    def test_empty_title_rejected(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(title="", source="https://test.com")

    def test_model_dump_for_storage(self) -> None:
        sko = SecurityKnowledgeObject(title="Test", source="https://test.com")
        data = sko.model_dump_for_storage()
        assert data["title"] == "Test"
        assert data["id"] == sko.id
        assert "created_at" in data

    def test_from_dict(self) -> None:
        original = SecurityKnowledgeObject(title="Test", source="https://test.com")
        data = original.model_dump_for_storage()
        restored = SecurityKnowledgeObject.from_dict(data)
        assert restored.title == "Test"
        assert restored.id == original.id
        assert restored.confidence == Confidence.UNKNOWN

    def test_updated_on_validation(self) -> None:
        sko = SecurityKnowledgeObject(title="Test", source="https://test.com")
        assert sko.updated_at is not None

    def test_direct_construction_with_lists(self) -> None:
        sko = SecurityKnowledgeObject(
            title="Test",
            source="https://test.com",
            tags=["a", "b"],
            bug_classes=[BugClass.XSS],
            technology=[Technology.REACT],
        )
        assert len(sko.tags) == 2
        assert len(sko.bug_classes) == 1
        assert len(sko.technology) == 1

    # ── v1 new field tests ────────────────────────────────────────

    def test_schema_version_default(self) -> None:
        sko = SecurityKnowledgeObject(title="T", source="https://test.com")
        assert sko.schema_version == 1

    def test_description_field(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            description="A detailed analysis",
        )
        assert sko.description == "A detailed analysis"

    def test_programming_language(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            programming_language=["Python", "Go"],
        )
        assert "Python" in sko.programming_language

    def test_operating_system(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            operating_system=["Linux", "Windows"],
        )
        assert "Linux" in sko.operating_system

    def test_interesting_endpoints(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            interesting_endpoints=["/api/v1/login", "/api/v1/admin"],
        )
        assert len(sko.interesting_endpoints) == 2

    def test_attack_surface(self) -> None:
        entry = AttackSurfaceEntry(
            name="Login endpoint",
            path="/api/v1/login",
            method="POST",
        )
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            attack_surface=[entry],
        )
        assert len(sko.attack_surface) == 1
        assert sko.attack_surface[0].name == "Login endpoint"

    def test_business_logic(self) -> None:
        concern = BusinessLogicConcern(
            description="Price modification during checkout",
            impact="Users could purchase items at arbitrary prices",
        )
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            business_logic=[concern],
        )
        assert len(sko.business_logic) == 1

    def test_authorization(self) -> None:
        auth = AuthorizationModel(
            model_type="RBAC",
            roles=["admin", "user"],
        )
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            authorization=[auth],
        )
        assert sko.authorization[0].model_type == "RBAC"

    def test_manual_test_checklist(self) -> None:
        item = ManualTestChecklistItem(
            step_id="AUTH-01",
            category="Authentication",
            description="Test for JWT none algorithm",
        )
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            manual_test_checklist=[item],
        )
        assert len(sko.manual_test_checklist) == 1

    def test_payload_references(self) -> None:
        payload = PayloadReference(
            payload="' OR 1=1 --",
            description="Basic SQLi bypass",
        )
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            payload_references=[payload],
        )
        assert sko.payload_references[0].payload == "' OR 1=1 --"

    def test_related_cwes(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            related_cwes=["CWE-79", "CWE-89"],
        )
        assert "CWE-79" in sko.related_cwes

    def test_normalized_content(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            raw_content="some raw text",
            normalized_content="some normalized text",
        )
        assert sko.normalized_content == "some normalized text"

    # ── v1 validation tests ──────────────────────────────────────

    def test_invalid_id_format(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(
                title="T", source="https://test.com",
                id="invalid-id",
            )

    def test_valid_custom_id(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="https://test.com",
            id="sko-aabbccddeeff",
        )
        assert sko.id == "sko-aabbccddeeff"

    def test_invalid_source_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(title="T", source="not-a-valid-source")

    def test_file_source_accepted(self) -> None:
        sko = SecurityKnowledgeObject(
            title="T", source="/tmp/test.md",
        )
        assert sko.source == "/tmp/test.md"

    def test_invalid_cwe_format_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(
                title="T", source="https://test.com",
                related_cwes=["CWE-79", "not-a-cwe"],
            )

    def test_schema_version_below_one_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(
                title="T", source="https://test.com",
                schema_version=0,
            )

    def test_round_trip_json_with_v1_fields(self) -> None:
        original = SecurityKnowledgeObject(
            title="Round Trip",
            source="https://test.com/roundtrip",
            description="A round-trip test",
            programming_language=["Python"],
            operating_system=["Linux"],
            interesting_endpoints=["/api/v1/status"],
            related_cwes=["CWE-79"],
        )
        data = original.model_dump_for_storage()
        restored = SecurityKnowledgeObject.from_dict(data)
        assert restored.title == original.title
        assert restored.id == original.id
        assert restored.description == original.description
        assert restored.programming_language == original.programming_language
        assert restored.operating_system == original.operating_system
        assert restored.interesting_endpoints == original.interesting_endpoints
        assert restored.related_cwes == original.related_cwes

    def test_backward_compat_minimal(self) -> None:
        """A minimal SKO (as old consumers would create it) must still work."""
        sko = SecurityKnowledgeObject(
            title="Minimal",
            source="https://test.com",
        )
        assert sko.description == ""
        assert sko.programming_language == []
        assert sko.operating_system == []
        assert sko.interesting_endpoints == []
        assert sko.attack_surface == []
        assert sko.business_logic == []
        assert sko.authorization == []
        assert sko.manual_test_checklist == []
        assert sko.payload_references == []
        assert sko.related_cwes == []
        assert sko.normalized_content is None
