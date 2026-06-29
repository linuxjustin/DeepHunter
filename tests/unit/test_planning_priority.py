"""Tests for the priority engine."""

from __future__ import annotations

import pytest

from deephunter.planning.models import PriorityWeights, RiskScore
from deephunter.planning.priority import PriorityEngine


class TestPriorityEngine:
    def test_default_weights(self) -> None:
        engine = PriorityEngine()
        assert engine.weights.likelihood == 0.30

    def test_calculate_zero(self) -> None:
        engine = PriorityEngine()
        assert engine.calculate() == 0.15

    def test_calculate_max(self) -> None:
        engine = PriorityEngine()
        score = engine.calculate(
            likelihood=10.0,
            impact=10.0,
            confidence=1.0,
            complexity=0.0,
            effort_hours=0.0,
            reward=1.0,
        )
        assert score == pytest.approx(1.0, abs=0.01)

    def test_calculate_high_priority(self) -> None:
        engine = PriorityEngine()
        score = engine.calculate(
            likelihood=9.0,
            impact=9.0,
            confidence=0.8,
            complexity=0.3,
            effort_hours=1.0,
            reward=0.9,
        )
        assert 0.8 <= score <= 1.0

    def test_calculate_low_priority(self) -> None:
        engine = PriorityEngine()
        score = engine.calculate(
            likelihood=1.0,
            impact=1.0,
            confidence=0.1,
            complexity=0.9,
            effort_hours=8.0,
            reward=0.1,
        )
        assert score < 0.5

    def test_score_clamped_to_zero(self) -> None:
        engine = PriorityEngine()
        score = engine.calculate(
            likelihood=-5.0, effort_hours=100.0,
        )
        assert score >= 0.0

    def test_score_clamped_to_one(self) -> None:
        engine = PriorityEngine()
        score = engine.calculate(
            likelihood=100.0,
            impact=100.0,
            confidence=10.0,
            reward=10.0,
        )
        assert score <= 1.0

    def test_calculate_from_risk(self) -> None:
        engine = PriorityEngine()
        risk = RiskScore(likelihood=8.0, impact=8.0, confidence=0.7)
        score = engine.calculate_from_risk(risk)
        assert 0.5 <= score <= 1.0

    def test_priority_label(self) -> None:
        engine = PriorityEngine()
        assert engine.priority_label(0.9) == "critical"
        assert engine.priority_label(0.7) == "high"
        assert engine.priority_label(0.5) == "medium"
        assert engine.priority_label(0.3) == "low"
        assert engine.priority_label(0.1) == "info"

    def test_custom_weights(self) -> None:
        weights = PriorityWeights(likelihood=0.0, impact=0.0, confidence=0.0, complexity_inverted=0.0, effort_inverted=0.0, reward=1.0)
        engine = PriorityEngine(weights=weights)
        score = engine.calculate(reward=1.0, likelihood=0.0, impact=0.0)
        assert score == pytest.approx(1.0, abs=0.01)

    def test_weight_normalization(self) -> None:
        weights = PriorityWeights(likelihood=10.0, impact=10.0, confidence=0.0, complexity_inverted=0.0, effort_inverted=0.0, reward=0.0)
        engine = PriorityEngine(weights=weights)
        score = engine.calculate(
            likelihood=10.0,
            impact=0.0,
            confidence=0.0,
            complexity=0.5,
            effort_hours=0.0,
            reward=0.0,
        )
        assert score == pytest.approx(0.5, abs=0.01)
