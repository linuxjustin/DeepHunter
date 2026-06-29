"""Tests for confidence scoring modules."""

from __future__ import annotations

import pytest

from deephunter.reasoning.confidence import (
    ConfidenceScorer,
    HypothesisStatusScorer,
    WeightedEvidenceScorer,
)
from deephunter.reasoning.models import (
    Evidence,
    EvidenceType,
    Experiment,
    ExperimentStatus,
    Observation,
    ObservationType,
)


class DummyScorer(ConfidenceScorer):
    def score(
        self,
        observations: list[Observation],
        evidence: list[Evidence],
        experiments: list[Experiment],
    ) -> float:
        return 0.5


class TestConfidenceScorer:
    def test_abc_cannot_instantiate(self) -> None:
        with pytest.raises(TypeError):
            ConfidenceScorer()  # type: ignore[abstract]

    def test_dummy_scorer(self) -> None:
        scorer = DummyScorer()
        assert scorer.score([], [], []) == 0.5


class TestWeightedEvidenceScorer:
    def test_no_evidence(self) -> None:
        scorer = WeightedEvidenceScorer()
        assert scorer.score([], [], []) == 0.1

    def test_evidence_increases_score(self) -> None:
        scorer = WeightedEvidenceScorer()
        ev = Evidence(observation_id="obs-1", content="evidence data", source="test")
        score = scorer.score([], [ev], [])
        assert score > 0.1

    def test_observations_increase_score(self) -> None:
        scorer = WeightedEvidenceScorer()
        obs = Observation(type="other", description="Test observation")
        score = scorer.score([obs], [], [])
        assert score > 0.1

    def test_more_evidence_gives_diminishing_returns(self) -> None:
        scorer = WeightedEvidenceScorer()
        evs = [Evidence(observation_id=f"obs-{i}", content=f"e{i}", source="t") for i in range(10)]
        s1 = scorer.score([], evs[:1], [])
        s10 = scorer.score([], evs, [])
        assert s10 > s1
        delta1 = s1 - 0.1
        delta10 = s10 - s1
        assert delta10 < delta1 * 9

    def test_passed_experiment_increases_score(self) -> None:
        scorer = WeightedEvidenceScorer()
        exp = Experiment(
            hypothesis_id="hyp-1",
            description="Test",
            procedure="P",
            expected_result="SQLi confirmed",
        )
        exp.status = ExperimentStatus.COMPLETED
        exp.actual_result = "SQLi confirmed on login endpoint"
        score = scorer.score([], [], [exp])
        assert score > 0.1

    def test_failed_experiment_decreases_score(self) -> None:
        scorer = WeightedEvidenceScorer()
        exp = Experiment(
            hypothesis_id="hyp-1",
            description="Test",
            procedure="P",
            expected_result="SQLi confirmed",
        )
        exp.status = ExperimentStatus.COMPLETED
        exp.actual_result = "No vulnerability found"
        score = scorer.score([], [], [exp])
        assert score < 0.1

    def test_mixed_experiments(self) -> None:
        scorer = WeightedEvidenceScorer()
        passed = Experiment(
            hypothesis_id="hyp-1", description="T1", procedure="P",
            expected_result="Vuln found", actual_result="Vuln found on endpoint",
        )
        passed.status = ExperimentStatus.COMPLETED
        failed = Experiment(
            hypothesis_id="hyp-1", description="T2", procedure="P",
            expected_result="RCE achieved", actual_result="No RCE",
        )
        failed.status = ExperimentStatus.COMPLETED
        score = scorer.score([], [], [passed, failed])
        assert 0.0 <= score <= 1.0

    def test_score_clamped_to_zero(self) -> None:
        scorer = WeightedEvidenceScorer()
        failed_many = [
            Experiment(
                hypothesis_id="hyp-1", description=f"T{i}", procedure="P",
                expected_result="Success", actual_result="Failed",
            )
            for i in range(10)
        ]
        for exp in failed_many:
            exp.status = ExperimentStatus.COMPLETED
        score = scorer.score([], [], failed_many)
        assert score >= 0.0

    def test_score_capped_at_one(self) -> None:
        scorer = WeightedEvidenceScorer()
        evs = [Evidence(observation_id=f"obs-{i}", content=f"e{i}", source="t") for i in range(100)]
        obs = [Observation(type="other", description=f"o{i}") for i in range(100)]
        exps = [
            Experiment(
                hypothesis_id="hyp-1", description=f"T{i}", procedure="P",
                expected_result="Match", actual_result="Match confirmed yes",
            )
            for i in range(20)
        ]
        for exp in exps:
            exp.status = ExperimentStatus.COMPLETED
        score = scorer.score(obs, evs, exps)
        assert score <= 1.0

    def test_planned_experiments_ignored(self) -> None:
        scorer = WeightedEvidenceScorer()
        exp = Experiment(
            hypothesis_id="hyp-1", description="Test", procedure="P",
            expected_result="Result",
        )
        assert exp.status == ExperimentStatus.PLANNED
        score = scorer.score([], [], [exp])
        assert score == 0.1  # only base, no experiment contribution


class TestHypothesisStatusScorer:
    def test_confirmed_with_high_confidence(self) -> None:
        exp = Experiment(
            hypothesis_id="hyp-1", description="T", procedure="P",
            expected_result="Vuln", actual_result="Vuln confirmed",
        )
        exp.status = ExperimentStatus.COMPLETED
        status = HypothesisStatusScorer.determine_status(0.8, [exp])
        assert status.value == "confirmed"

    def test_refuted_with_failed_experiment(self) -> None:
        exp = Experiment(
            hypothesis_id="hyp-1", description="T", procedure="P",
            expected_result="No RCE here", actual_result="No output",
        )
        exp.status = ExperimentStatus.COMPLETED
        status = HypothesisStatusScorer.determine_status(0.3, [exp])
        assert status.value == "refuted"

    def test_investigating_moderate_confidence(self) -> None:
        status = HypothesisStatusScorer.determine_status(0.6, [])
        assert status.value == "investigating"

    def test_proposed_low_confidence(self) -> None:
        status = HypothesisStatusScorer.determine_status(0.2, [])
        assert status.value == "proposed"

    def test_inconclusive_zero_confidence(self) -> None:
        status = HypothesisStatusScorer.determine_status(0.0, [])
        assert status.value == "inconclusive"

    def test_both_passed_and_failed(self) -> None:
        passed = Experiment(
            hypothesis_id="hyp-1", description="T1", procedure="P",
            expected_result="Found", actual_result="Found XSS",
        )
        passed.status = ExperimentStatus.COMPLETED
        failed = Experiment(
            hypothesis_id="hyp-1", description="T2", procedure="P",
            expected_result="RCE", actual_result="No RCE",
        )
        failed.status = ExperimentStatus.COMPLETED
        status = HypothesisStatusScorer.determine_status(0.8, [passed, failed])
        # If any passed and confidence >= 0.7, it's confirmed
        assert status.value == "confirmed"
