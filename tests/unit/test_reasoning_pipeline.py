"""Tests for the reasoning pipeline."""

from __future__ import annotations

import pytest

from deephunter.core.types import BugClass, Technology
from deephunter.reasoning.models import HypothesisPriority, HypothesisStatus
from deephunter.reasoning.pipeline import (
    ConfidenceUpdateStage,
    EvidenceCollectionStage,
    ExperimentPlanningStage,
    FindingCreationStage,
    HypothesisGenerationStage,
    ObservationStage,
    PipelineReport,
    PivotGenerationStage,
    PrioritizationStage,
    ReasoningPipeline,
    ReasoningStage,
    ReportHookStage,
    ResultRecordingStage,
)
from deephunter.reasoning.session import InvestigationSession


class TestReasoningStage:
    def test_base_stage_name_default(self) -> None:
        assert ReasoningStage.name == ""


class TestObservationStage:
    def test_creates_observation_from_target(self) -> None:
        session = InvestigationSession.new("https://example.com")
        stage = ObservationStage()
        stage.process(session)
        assert len(session.state.observations) >= 1

    def test_skips_if_observations_exist(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.create_observation("other", description="Manual observation")
        stage = ObservationStage()
        stage.process(session)
        assert len(session.state.observations) == 1


class TestEvidenceCollectionStage:
    def test_creates_evidence_for_observations(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.create_observation("other", description="Test", source="nmap")
        stage = EvidenceCollectionStage()
        stage.process(session)
        assert len(session.state.evidence) >= 1

    def test_skips_observations_without_source(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.create_observation("other", description="Test")
        stage = EvidenceCollectionStage()
        stage.process(session)
        assert len(session.state.evidence) == 0

    def test_does_not_duplicate_evidence(self) -> None:
        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation("other", description="Test", source="src")
        session.add_evidence(observation_id=obs.id, content="Existing", source="src")
        stage = EvidenceCollectionStage()
        stage.process(session)
        assert len(session.state.evidence) == 1


class TestHypothesisGenerationStage:
    def test_creates_hypothesis_from_fingerprint(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.state.technology_fingerprint.technologies = [Technology.FLASK]
        stage = HypothesisGenerationStage()
        stage.process(session)
        assert len(session.state.hypotheses) == 1

    def test_skips_if_hypotheses_exist(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.create_hypothesis(title="Manual", description="Manual")
        stage = HypothesisGenerationStage()
        stage.process(session)
        assert len(session.state.hypotheses) == 1

    def test_default_technology_if_no_fingerprint(self) -> None:
        session = InvestigationSession.new("https://example.com")
        stage = HypothesisGenerationStage()
        stage.process(session)
        assert len(session.state.hypotheses) == 1


class TestPrioritizationStage:
    def test_sorts_by_priority(self) -> None:
        session = InvestigationSession.new("https://example.com")
        h1 = session.create_hypothesis(title="Low priority", description="Test")
        h2 = session.create_hypothesis(title="Medium priority", description="Test")
        h3 = session.create_hypothesis(title="High priority", description="Test")
        h1.bug_classes = [BugClass.XSS]
        h2.bug_classes = [BugClass.SSRF]
        h3.bug_classes = [BugClass.RCE]

        stage = PrioritizationStage()
        stage.process(session)

        titles = [h.title for h in session.state.hypotheses]
        assert titles[0] == "High priority"

    def test_runs_without_hypotheses(self) -> None:
        session = InvestigationSession.new("https://example.com")
        stage = PrioritizationStage()
        stage.process(session)


class TestExperimentPlanningStage:
    def test_creates_experiments_for_high_confidence(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        hyp.confidence = 0.5
        stage = ExperimentPlanningStage()
        stage.process(session)
        assert len(session.state.experiments) >= 1

    def test_skips_low_confidence(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        hyp.confidence = 0.1
        stage = ExperimentPlanningStage()
        stage.process(session)
        assert len(session.state.experiments) == 0

    def test_does_not_duplicate(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        hyp.confidence = 0.5
        exp = session.create_experiment(
            hypothesis_id=hyp.id,
            description="Existing",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp is not None
        stage = ExperimentPlanningStage()
        stage.process(session)
        assert len(session.state.experiments) == 1


class TestResultRecordingStage:
    def test_noop(self) -> None:
        session = InvestigationSession.new("https://example.com")
        stage = ResultRecordingStage()
        stage.process(session)


class TestConfidenceUpdateStage:
    def test_confidence_updated(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="Test", description="Test")
        exp = session.create_experiment(
            hypothesis_id=hyp.id,
            description="Test",
            procedure="Proc",
            expected_result="Result",
        )
        assert exp is not None
        exp.status = "completed"

        stage = ConfidenceUpdateStage()
        stage.process(session)

        updated = [h for h in session.state.hypotheses if h.id == hyp.id][0]
        assert updated.confidence >= 0

    def test_no_experiments(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.create_hypothesis(title="Test", description="Test")
        stage = ConfidenceUpdateStage()
        stage.process(session)


class TestPivotGenerationStage:
    def test_creates_pivot_for_completed_experiment(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="Test", description="Test")
        exp = session.create_experiment(
            hypothesis_id=hyp.id,
            description="Test",
            procedure="Proc",
            expected_result="Result",
        )
        assert exp is not None
        session.record_result(experiment_id=exp.id, status="completed", actual_result="Found")

        stage = PivotGenerationStage()
        stage.process(session)

        assert len(session.state.pivots) >= 1

    def test_skips_planned_experiments(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="Test", description="Test")
        session.create_experiment(
            hypothesis_id=hyp.id,
            description="Test",
            procedure="Proc",
            expected_result="Result",
        )
        stage = PivotGenerationStage()
        stage.process(session)
        assert len(session.state.pivots) == 0

    def test_does_not_duplicate_pivots(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="Test", description="Test")
        exp = session.create_experiment(
            hypothesis_id=hyp.id,
            description="Test",
            procedure="Proc",
            expected_result="Result",
        )
        assert exp is not None
        session.record_result(experiment_id=exp.id, status="completed", actual_result="Found")
        session.create_pivot(description="Pivot", rationale="R", reason="other", source_experiment_id=exp.id)

        stage = PivotGenerationStage()
        stage.process(session)
        assert len(session.state.pivots) == 1


class TestFindingCreationStage:
    def test_creates_finding_for_confirmed_hypothesis(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        hyp.status = HypothesisStatus.CONFIRMED
        exp = session.create_experiment(
            hypothesis_id=hyp.id,
            description="Test",
            procedure="Proc",
            expected_result="Result",
        )
        assert exp is not None
        exp.status = "completed"
        exp.actual_result = "Found SQL injection"

        stage = FindingCreationStage()
        stage.process(session)

        assert len(session.state.findings) == 1
        assert session.state.findings[0].hypothesis_id == hyp.id

    def test_skips_if_finding_exists(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        hyp.finding_id = "fnd-1"
        exp = session.create_experiment(
            hypothesis_id=hyp.id,
            description="Test",
            procedure="Proc",
            expected_result="Result",
        )
        assert exp is not None
        exp.status = "completed"
        exp.actual_result = "Found"

        stage = FindingCreationStage()
        stage.process(session)
        assert len(session.state.findings) == 0

    def test_skips_non_confirmed(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        hyp.status = HypothesisStatus.REFUTED
        exp = session.create_experiment(
            hypothesis_id=hyp.id,
            description="Test",
            procedure="Proc",
            expected_result="Result",
        )
        assert exp is not None
        exp.status = "completed"
        exp.actual_result = "Found"

        stage = FindingCreationStage()
        stage.process(session)
        assert len(session.state.findings) == 0


class TestReportHookStage:
    def test_noop(self) -> None:
        session = InvestigationSession.new("https://example.com")
        stage = ReportHookStage()
        stage.process(session)


class TestReasoningPipeline:
    def test_run_creates_full_investigation(self) -> None:
        session = InvestigationSession.new("https://example.com/")
        pipeline = ReasoningPipeline()
        report = pipeline.run(session)

        assert isinstance(report, PipelineReport)
        assert len(report.stage_times) == 10
        assert report.total_seconds > 0

    def test_report_contains_all_stages(self) -> None:
        session = InvestigationSession.new("https://example.com")
        pipeline = ReasoningPipeline()
        report = pipeline.run(session)

        expected_stages = {
            "observation",
            "evidence_collection",
            "hypothesis_generation",
            "prioritization",
            "experiment_planning",
            "result_recording",
            "confidence_update",
            "pivot_generation",
            "finding_creation",
            "report_hook",
        }
        assert set(report.stage_times.keys()) == expected_stages

    def test_runs_on_empty_session(self) -> None:
        session = InvestigationSession.new("https://example.com")
        pipeline = ReasoningPipeline()
        report = pipeline.run(session)
        assert report.total_seconds > 0

    def test_stage_failure_does_not_crash_pipeline(self) -> None:
        session = InvestigationSession.new("https://example.com")
        pipeline = ReasoningPipeline()

        class CrashingStage(ReasoningStage):
            name = "crash"

            def process(self, session: InvestigationSession) -> None:
                raise RuntimeError("simulated crash")

        pipeline._stages.insert(0, CrashingStage())
        report = pipeline.run(session)
        assert report.total_seconds > 0


class TestPipelineReport:
    def test_defaults(self) -> None:
        report = PipelineReport()
        assert report.stage_times == {}
        assert report.total_seconds == 0.0
