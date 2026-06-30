"""Tests for the reasoning engine."""

from __future__ import annotations

import pytest

from deephunter.core.types import BugClass, Technology
from deephunter.rag.retriever import Retriever
from deephunter.reasoning.hypothesis import HypothesisGenerator
from deephunter.reasoning.models import Hypothesis, HypothesisPriority


class TestHypothesis:
    def test_create(self) -> None:
        hyp = Hypothesis(
            title="Test SQL injection",
            description="Test description",
            bug_classes=[BugClass.SQL_INJECTION],
        )
        assert hyp.id.startswith("hyp-")
        assert hyp.priority == HypothesisPriority.MEDIUM
        assert hyp.confidence == 0.0

    def test_high_priority(self) -> None:
        hyp = Hypothesis(
            title="Critical RCE",
            priority=HypothesisPriority.CRITICAL,
        )
        assert hyp.priority == HypothesisPriority.CRITICAL

    def test_to_dict(self) -> None:
        hyp = Hypothesis(
            title="Test",
            description="Desc",
            bug_classes=[BugClass.XSS],
        )
        d = hyp.to_dict()
        assert d["title"] == "Test"
        assert d["bug_classes"] == ["xss"]
        assert "created_at" in d


class TestHypothesisGenerator:
    def test_generate_with_populated_store(self, sample_config, populated_store) -> None:
        retriever = Retriever(sample_config.rag, populated_store)
        retriever.index()

        gen = HypothesisGenerator(populated_store, retriever, sample_config.reasoning)
        hypotheses = gen.generate("web application security testing")
        assert isinstance(hypotheses, list)
        # Should have some hypotheses based on the stored SKOs
        assert len(hypotheses) > 0

    def test_generate_empty_no_skos(self, sample_config, empty_store) -> None:
        retriever = Retriever(sample_config.rag, empty_store)
        gen = HypothesisGenerator(empty_store, retriever, sample_config.reasoning)

        with pytest.raises(Exception):
            gen.generate("test")

    def test_confidence_from_count(self) -> None:
        from deephunter.core.types import Confidence as C

        gen = HypothesisGenerator.__new__(HypothesisGenerator)
        assert gen._confidence_from_count(5) == C.HIGH
        assert gen._confidence_from_count(3) == C.MEDIUM
        assert gen._confidence_from_count(1) == C.LOW
        assert gen._confidence_from_count(0) == C.LOW

    def test_priority_from_confidence(self) -> None:
        from deephunter.core.types import Confidence as C

        mapping = [
            (C.HIGH, HypothesisPriority.CRITICAL),
            (C.MEDIUM, HypothesisPriority.HIGH),
            (C.LOW, HypothesisPriority.MEDIUM),
            (C.UNKNOWN, HypothesisPriority.LOW),
        ]
        gen = HypothesisGenerator.__new__(HypothesisGenerator)
        for conf, expected in mapping:
            assert gen._priority_from_confidence(conf) == expected
