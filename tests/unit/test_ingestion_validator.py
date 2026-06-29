"""Tests for SKOValidator and ValidationReport."""

from __future__ import annotations

import pytest

from deephunter.ingestion.validator import SKOValidator, ValidationReport
from deephunter.knowledge.models import SecurityKnowledgeObject


class TestSKOValidator:
    def test_valid_sko(self) -> None:
        sko = SecurityKnowledgeObject(
            title="Test",
            source="https://test.com",
        )
        valid, errors = SKOValidator.validate_and_report(sko)
        assert valid is True
        assert errors == []

    def test_invalid_empty_title_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(title="  ", source="https://test.com")

    def test_invalid_source_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(title="Test", source="not-valid")

    def test_validate_batch(self) -> None:
        skos = [
            SecurityKnowledgeObject(title="A", source="https://a.com"),
            SecurityKnowledgeObject(title="B", source="https://b.com"),
        ]
        report = SKOValidator.validate_batch(skos)
        assert report.total == 2
        assert report.passed == 2
        assert report.failed == 0

    def test_validation_report_properties(self) -> None:
        report = ValidationReport(total=10, passed=7, failed=3)
        assert report.failure_rate == 0.3

    def test_validation_report_empty(self) -> None:
        report = ValidationReport()
        assert report.failure_rate == 0.0

    def test_validation_report_merge(self) -> None:
        r1 = ValidationReport(total=5, passed=4, failed=1)
        r2 = ValidationReport(total=3, passed=2, failed=1)
        r1.merge(r2)
        assert r1.total == 8
        assert r1.passed == 6
        assert r1.failed == 2

    def test_valid_cwe(self) -> None:
        sko = SecurityKnowledgeObject(
            title="Test",
            source="https://test.com",
            related_cwes=["CWE-79"],
        )
        valid, errors = SKOValidator.validate_and_report(sko)
        assert valid is True

    def test_invalid_id_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityKnowledgeObject(
                title="Test",
                source="https://test.com",
                id="bad-id",
            )
