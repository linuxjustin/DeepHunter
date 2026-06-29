"""Confidence scoring for the Reasoning Engine.

Confidence is a numeric value between 0.0 and 1.0 that reflects
how strongly a hypothesis is supported by available evidence.

The scoring is evidence-weighted: more evidence → higher potential
confidence.  Passed experiments increase confidence; failed ones
decrease it.

The design is deliberately simple and pluggable.  Future implementations
can replace the scoring algorithm without changing the callers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from deephunter.reasoning.models import (
    Evidence,
    Experiment,
    ExperimentStatus,
    HypothesisStatus,
    Observation,
)


class ConfidenceScorer(ABC):
    """Abstract interface for confidence scoring algorithms.

    Implementations take the evidence and experiments associated
    with a hypothesis and return a confidence score.
    """

    @abstractmethod
    def score(
        self,
        observations: list[Observation],
        evidence: list[Evidence],
        experiments: list[Experiment],
    ) -> float:
        """Compute a confidence score.

        Args:
            observations: Observations supporting the hypothesis.
            evidence: Evidence backing the observations.
            experiments: Experiments run against the hypothesis.

        Returns:
            A float between 0.0 (no confidence) and 1.0 (certain).
        """


class WeightedEvidenceScorer(ConfidenceScorer):
    """Default confidence scorer based on evidence volume and experiment outcomes.

    Scoring logic:

    - Base confidence starts at 0.1 (a hypothesis with nothing).
    - Each piece of evidence adds up to 0.15 (diminishing returns
      after 5 pieces).
    - Each observation adds up to 0.1.
    - Completed experiments that match expectations: +0.2 each.
    - Failed experiments: -0.3 each.
    - Score is clamped to [0.0, 1.0].
    """

    _EVIDENCE_MAX = 0.15
    _EVIDENCE_HALF_LIFE = 5
    _OBSERVATION_MAX = 0.1
    _OBSERVATION_HALF_LIFE = 3
    _EXPERIMENT_PASS = 0.2
    _EXPERIMENT_FAIL = -0.3
    _BASE = 0.1

    def score(
        self,
        observations: list[Observation],
        evidence: list[Evidence],
        experiments: list[Experiment],
    ) -> float:
        score_val = self._BASE

        # Evidence contribution (diminishing returns)
        ev_count = len(evidence)
        if ev_count > 0:
            score_val += self._EVIDENCE_MAX * (
                1.0 - 2.0 ** (-ev_count / self._EVIDENCE_HALF_LIFE)
            )

        # Observation contribution
        obs_count = len(observations)
        if obs_count > 0:
            score_val += self._OBSERVATION_MAX * (
                1.0 - 2.0 ** (-obs_count / self._OBSERVATION_HALF_LIFE)
            )

        # Experiment contributions
        for exp in experiments:
            if exp.status == ExperimentStatus.COMPLETED:
                if exp.actual_result and exp.expected_result:
                    if self._matches_expected(exp):
                        score_val += self._EXPERIMENT_PASS
                    else:
                        score_val += self._EXPERIMENT_FAIL

        return max(0.0, min(1.0, score_val))

    @staticmethod
    def _matches_expected(exp: Experiment) -> bool:
        """Heuristic: does the actual result match the expected result?

        Compares lowercase text overlap.  This is intentionally simple;
        future scorers can use LLM-based or semantic comparison.
        """
        expected = exp.expected_result.lower().strip()
        actual = exp.actual_result.lower().strip()
        if not expected or not actual:
            return False
        return expected in actual or actual in expected


class HypothesisStatusScorer:
    """Determines hypothesis status based on confidence score and experiment outcomes."""

    @staticmethod
    def determine_status(
        confidence: float,
        experiments: list[Experiment],
    ) -> HypothesisStatus:
        """Determine the status of a hypothesis.

        Args:
            confidence: Current confidence score (0.0-1.0).
            experiments: List of experiments for this hypothesis.

        Returns:
            The appropriate HypothesisStatus.
        """
        has_failed_experiment = any(
            e.status == ExperimentStatus.COMPLETED
            and e.actual_result.strip()
            and not (
                e.expected_result.lower().strip() in e.actual_result.lower().strip()
            )
            for e in experiments
        )

        has_passed_experiment = any(
            e.status == ExperimentStatus.COMPLETED
            and e.actual_result.strip()
            and (
                e.expected_result.lower().strip() in e.actual_result.lower().strip()
            )
            for e in experiments
        )

        if has_failed_experiment and not has_passed_experiment:
            return HypothesisStatus.REFUTED

        if has_passed_experiment and confidence >= 0.7:
            return HypothesisStatus.CONFIRMED

        if confidence > 0.5:
            return HypothesisStatus.INVESTIGATING

        if confidence > 0.0:
            return HypothesisStatus.PROPOSED

        return HypothesisStatus.INCONCLUSIVE
