"""Tests for reasoning engine core models."""

from __future__ import annotations

from deephunter.core.types import BugClass, Technology
from deephunter.reasoning.models import (
    EdgeType,
    Evidence,
    EvidenceType,
    Experiment,
    ExperimentStatus,
    Finding,
    FindingSeverity,
    HypothesisStatus,
    Investigation,
    InvestigationState,
    NodeType,
    Observation,
    ObservationType,
    Pivot,
    PivotReason,
    TechnologyFingerprint,
)


class TestObservation:
    def test_create_minimal(self) -> None:
        obs = Observation(type=ObservationType.OTHER, description="Server is running")
        assert obs.id.startswith("obs-")
        assert obs.type == ObservationType.OTHER
        assert obs.description == "Server is running"

    def test_id_prefix(self) -> None:
        obs = Observation(type=ObservationType.OTHER, description="x")
        assert obs.id.startswith("obs-")

    def test_default_detail(self) -> None:
        obs = Observation(type=ObservationType.OTHER, description="x")
        assert obs.detail == ""
        assert obs.source == ""
        assert obs.tags == []


class TestEvidence:
    def test_create_minimal(self) -> None:
        ev = Evidence(observation_id="obs-1", content="Evidence content", source="test")
        assert ev.id.startswith("ev-")
        assert ev.type == EvidenceType.RAW

    def test_default_type_is_raw(self) -> None:
        ev = Evidence(observation_id="obs-1", content="c", source="s")
        assert ev.type == EvidenceType.RAW

    def test_evidence_type_variants(self) -> None:
        for et in EvidenceType:
            ev = Evidence(observation_id="obs-1", content="c", source="s", type=et)
            assert ev.type == et


class TestExperiment:
    def test_create_minimal(self) -> None:
        exp = Experiment(
            hypothesis_id="hyp-1",
            description="Test for SQLi",
            procedure="Send payloads",
            expected_result="RCE",
        )
        assert exp.id.startswith("exp-")
        assert exp.status == ExperimentStatus.PLANNED

    def test_default_status(self) -> None:
        exp = Experiment(
            hypothesis_id="hyp-1",
            description="Test",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp.status == ExperimentStatus.PLANNED

    def test_completed_experiment(self) -> None:
        exp = Experiment(
            hypothesis_id="hyp-1",
            description="Test",
            procedure="P",
            expected_result="RCE",
        )
        exp.status = ExperimentStatus.COMPLETED
        exp.actual_result = "RCE confirmed"
        assert exp.status == ExperimentStatus.COMPLETED


class TestPivot:
    def test_create_minimal(self) -> None:
        pvt = Pivot(
            description="New direction",
            rationale="Previous path blocked",
            reason=PivotReason.HYPOTHESIS_REFUTED,
            source_experiment_id="exp-1",
        )
        assert pvt.id.startswith("pvt-")
        assert pvt.reason == PivotReason.HYPOTHESIS_REFUTED

    def test_reason_string_coercion(self) -> None:
        pvt = Pivot(
            description="x",
            rationale="y",
            reason="partial_confirmation",
            source_experiment_id="exp-1",
        )
        assert pvt.reason == PivotReason.PARTIAL_CONFIRMATION


class TestFinding:
    def test_create_minimal(self) -> None:
        fnd = Finding(
            title="SQL Injection Found",
            hypothesis_id="hyp-1",
            description="Found in login endpoint",
            bug_classes=[BugClass.SQL_INJECTION],
            severity=FindingSeverity.CRITICAL,
            experiment_ids=["exp-1"],
        )
        assert fnd.id.startswith("fnd-")
        assert fnd.severity == FindingSeverity.CRITICAL
        assert BugClass.SQL_INJECTION in fnd.bug_classes

    def test_default_severity(self) -> None:
        fnd = Finding(
            title="T",
            hypothesis_id="hyp-1",
            description="D",
            bug_classes=[],
            experiment_ids=[],
        )
        assert fnd.severity == FindingSeverity.MEDIUM


class TestTechnologyFingerprint:
    def test_default_values(self) -> None:
        fp = TechnologyFingerprint()
        assert fp.operating_systems == []
        assert fp.technologies == []
        assert fp.frameworks == []

    def test_with_technology_enum(self) -> None:
        fp = TechnologyFingerprint(
            technologies=[Technology.FLASK, Technology.NODEJS],
        )
        assert Technology.FLASK in fp.technologies


class TestInvestigationState:
    def test_initial_state(self) -> None:
        state = InvestigationState(target="https://example.com")
        assert state.observations == []
        assert state.evidence == []
        assert state.hypotheses == []
        assert state.experiments == []
        assert state.pivots == []
        assert state.findings == []
        assert isinstance(state.technology_fingerprint, TechnologyFingerprint)

    def test_target_required(self) -> None:
        state = InvestigationState(target="https://example.com")
        assert state.target == "https://example.com"


class TestInvestigation:
    def test_create_minimal(self) -> None:
        inv = Investigation(target="https://example.com")
        assert inv.id.startswith("inv-")
        assert inv.target == "https://example.com"
        assert isinstance(inv.state, InvestigationState)

    def test_state_has_default_target(self) -> None:
        inv = Investigation(target="https://example.com")
        assert inv.state.target == ""

    def test_id_prefix(self) -> None:
        inv = Investigation(target="x")
        assert inv.id.startswith("inv-")

    def test_serialization_round_trip(self) -> None:
        inv = Investigation(target="https://example.com")
        obs = Observation(type=ObservationType.OTHER, description="First observation")
        inv.state.observations.append(obs)

        data = inv.model_dump(mode="json")
        restored = Investigation.model_validate(data)

        assert restored.id == inv.id
        assert restored.target == inv.target
        assert len(restored.state.observations) == 1
        assert restored.state.observations[0].id == obs.id

    def test_serialization_json(self) -> None:
        inv = Investigation(target="https://example.com")
        ev = Evidence(observation_id="obs-1", content="data", source="src")
        inv.state.evidence.append(ev)

        as_json = inv.model_dump_json()
        restored = Investigation.model_validate_json(as_json)

        assert len(restored.state.evidence) == 1
        assert restored.state.evidence[0].content == "data"

    def test_hypotheses_as_dicts(self) -> None:
        inv = Investigation(target="x")
        inv.state.hypotheses = [
            {"id": "hyp-1", "title": "H1"},
            {"id": "hyp-2", "title": "H2"},
        ]
        assert len(inv.state.hypotheses) == 2
        assert inv.state.hypotheses[0]["title"] == "H1"
