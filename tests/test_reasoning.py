"""Tests for the reasoning engine."""

from __future__ import annotations

import pytest

from deephunter.core.config import ReasoningConfig
from deephunter.core.types import BugClass, Confidence
from deephunter.rag.retriever import Retriever
from deephunter.reasoning.hypothesis import (
    Hypothesis,
    HypothesisGenerator,
    HypothesisPriority,
)


class TestHypothesis:
    def test_create(self) -> None:
        hyp = Hypothesis(
            title="Test SQL injection",
            description="Test description",
            bug_classes=[BugClass.SQL_INJECTION],
        )
        assert hyp.id.startswith("hyp-")
        assert hyp.priority == HypothesisPriority.MEDIUM
        assert hyp.confidence == Confidence.UNKNOWN

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
        assert "created" in d


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
        assert HypothesisGenerator._confidence_from_count(5) == Confidence.HIGH
        assert HypothesisGenerator._confidence_from_count(3) == Confidence.MEDIUM
        assert HypothesisGenerator._confidence_from_count(1) == Confidence.LOW
        assert HypothesisGenerator._confidence_from_count(0) == Confidence.LOW

    def test_priority_from_confidence(self) -> None:
        mapping = [
            (Confidence.HIGH, HypothesisPriority.CRITICAL),
            (Confidence.MEDIUM, HypothesisPriority.HIGH),
            (Confidence.LOW, HypothesisPriority.MEDIUM),
            (Confidence.UNKNOWN, HypothesisPriority.LOW),
        ]
        for conf, expected in mapping:
            assert HypothesisGenerator._priority_from_confidence(conf) == expected