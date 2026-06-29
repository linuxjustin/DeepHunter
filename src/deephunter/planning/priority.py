"""Priority engine — weighted scoring for investigation steps.

Computes a 0.0–1.0 priority score from multiple input factors
using configurable weights.
"""

from __future__ import annotations

from deephunter.planning.models import PriorityWeights, RiskScore


class PriorityEngine:
    """Calculates priority scores using configurable weights.

    Usage::

        engine = PriorityEngine()
        score = engine.calculate(
            likelihood=7.0,
            impact=8.0,
            confidence=0.6,
            complexity=0.3,
            effort_hours=2.0,
            reward=0.7,
        )
    """

    def __init__(self, weights: PriorityWeights | None = None) -> None:
        self._weights = weights or PriorityWeights()
        self._weights.normalize()

    @property
    def weights(self) -> PriorityWeights:
        return self._weights

    def calculate(
        self,
        likelihood: float = 0.0,
        impact: float = 0.0,
        confidence: float = 0.0,
        complexity: float = 0.5,
        effort_hours: float = 0.0,
        reward: float = 0.0,
    ) -> float:
        """Calculate a priority score from component factors.

        Args:
            likelihood: How likely the vulnerability exists (0–10).
            impact: Potential impact if confirmed (0–10).
            confidence: Confidence in the hypothesis (0–1).
            complexity: Technical complexity of testing (0–1, higher = harder).
            effort_hours: Estimated manual effort in hours.
            reward: Potential reward / value (0–1).

        Returns:
            A priority score between 0.0 and 1.0.
        """
        norm_likelihood = likelihood / 10.0
        norm_impact = impact / 10.0
        norm_effort = max(0.0, 1.0 - (effort_hours / 8.0))
        norm_complexity = 1.0 - complexity

        score = (
            self._weights.likelihood * norm_likelihood
            + self._weights.impact * norm_impact
            + self._weights.confidence * confidence
            + self._weights.complexity_inverted * norm_complexity
            + self._weights.effort_inverted * norm_effort
            + self._weights.reward * reward
        )

        return round(max(0.0, min(1.0, score)), 4)

    def calculate_from_risk(self, risk: RiskScore, **extra: float) -> float:
        """Calculate priority from a RiskScore object plus extras."""
        return self.calculate(
            likelihood=risk.likelihood,
            impact=risk.impact,
            confidence=risk.confidence,
            **extra,
        )

    def priority_label(self, score: float) -> str:
        """Map a numeric score to a human-readable label."""
        if score >= 0.8:
            return "critical"
        if score >= 0.6:
            return "high"
        if score >= 0.4:
            return "medium"
        if score >= 0.2:
            return "low"
        return "info"
