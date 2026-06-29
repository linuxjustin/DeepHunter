"""SKO validation for the ingestion pipeline.

Validates every SecurityKnowledgeObject before storage.  Failures
are collected into a ``ValidationReport`` so the pipeline can
continue processing without crashing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of validating a single SKO."""

    sko_id: str
    valid: bool
    errors: list[str] = field(default_factory=list)


@dataclass
class ValidationReport:
    """Aggregate validation report for a pipeline run."""

    total: int = 0
    passed: int = 0
    failed: int = 0
    results: list[ValidationResult] = field(default_factory=list)

    @property
    def failure_rate(self) -> float:
        """Return the fraction of SKOs that failed validation (0.0 to 1.0)."""
        if self.total == 0:
            return 0.0
        return self.failed / self.total

    def merge(self, other: ValidationReport) -> None:
        """Merge another report into this one."""
        self.total += other.total
        self.passed += other.passed
        self.failed += other.failed
        self.results.extend(other.results)


class SKOValidator:
    """Validates SecurityKnowledgeObject instances.

    Uses Pydantic's built-in validation but catches errors instead
    of raising, reporting them through a ``ValidationReport``.
    """

    @staticmethod
    def validate(sko: SecurityKnowledgeObject) -> ValidationResult:
        """Validate an SKO and return the result.

        The SKO object itself is not mutated.  If validation fails,
        the errors are captured but no exception is raised.
        """
        errors: list[str] = []
        try:
            sko.model_dump(mode="json")
        except PydanticValidationError as exc:
            for err in exc.errors():
                loc = ".".join(str(l) for l in err["loc"])
                msg = err.get("msg", str(err["type"]))
                errors.append(f"{loc}: {msg}")
        return ValidationResult(sko_id=sko.id, valid=len(errors) == 0, errors=errors)

    @classmethod
    def validate_batch(
        cls, skos: list[SecurityKnowledgeObject]
    ) -> ValidationReport:
        """Validate multiple SKOs, returning a report.

        Args:
            skos: The SKOs to validate.

        Returns:
            A ``ValidationReport`` with per-SKO results.
        """
        report = ValidationReport()
        for sko in skos:
            result = cls.validate(sko)
            report.total += 1
            if result.valid:
                report.passed += 1
            else:
                report.failed += 1
                logger.warning("Validation failed for %s: %s", sko.id, result.errors)
            report.results.append(result)
        return report

    @classmethod
    def validate_and_report(
        cls, sko: SecurityKnowledgeObject
    ) -> tuple[bool, list[str]]:
        """Convenience: validate one SKO and return ``(is_valid, errors)``.

        This is the simplest API for callers that want a quick check.
        """
        result = cls.validate(sko)
        return result.valid, result.errors
