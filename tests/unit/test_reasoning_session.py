"""Tests for InvestigationSession."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.reasoning.events import (
    HypothesisCreatedEvent,
    ObservationCreatedEvent,
)
from deephunter.reasoning.session import InvestigationSession


class TestInvestigationSession:
    def test_create_new(self) -> None:
        session = InvestigationSession.new("https://example.com")
        assert session.investigation.target == "https://example.com"
        assert session.investigation.id.startswith("inv-")
        assert session.state.target == "https://example.com"

    def test_new_with_name(self) -> None:
        session = InvestigationSession.new("https://example.com", name="Test Investigation")
        assert session.investigation.name == "Test Investigation"

    def test_load_save_roundtrip(self, tmp_path: Path) -> None:
        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation(
            "network", description="Open port 443", source="nmap",
        )
        path = tmp_path / "session.json"
        session.save(str(path))

        loaded = InvestigationSession.load(str(path))
        assert loaded.investigation.target == "https://example.com"
        assert loaded.investigation.id == session.investigation.id
        assert len(loaded.state.observations) == 1
        assert loaded.state.observations[0].id == obs.id

    def test_load_nonexistent(self) -> None:
        with pytest.raises(FileNotFoundError):
            InvestigationSession.load("/nonexistent/path.json")

    def test_create_observation(self) -> None:
        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation(
            "technology", description="Discovered Apache server", source="nmap scan",
        )
        assert obs.id.startswith("obs-")
        assert obs.type.value == "technology"
        assert obs.description == "Discovered Apache server"
        assert len(session.state.observations) == 1

    def test_create_observation_fires_event(self) -> None:
        session = InvestigationSession.new("https://example.com")
        received = []

        session.events.subscribe(ObservationCreatedEvent, lambda e: received.append(e))
        session.create_observation("other", description="Test observation")
        assert len(received) == 1

    def test_add_evidence(self) -> None:
        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation("other", description="Suspicious response")
        ev = session.add_evidence(
            observation_id=obs.id,
            content="Response includes stack trace",
            source="burp",
        )
        assert ev is not None
        assert ev.id.startswith("ev-")
        assert ev.observation_id == obs.id
        assert len(session.state.evidence) == 1

    def test_add_evidence_no_observation(self) -> None:
        session = InvestigationSession.new("https://example.com")
        ev = session.add_evidence(observation_id="obs-nonexistent", content="x", source="s")
        assert ev is None

    def test_create_hypothesis(self) -> None:
        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation("other", description="Reflected input in response")

        hyp = session.create_hypothesis(
            title="Test for XSS",
            description="Check if input is sanitized",
            technologies=["react", "nodejs"],
            observation_ids=[obs.id],
        )
        assert hyp["id"].startswith("hyp-")
        assert hyp["title"] == "Test for XSS"
        assert obs.id in hyp.get("observation_ids", [])
        assert len(session.state.hypotheses) == 1

    def test_create_hypothesis_no_graph_node(self) -> None:
        """Hypotheses are stored as dicts, not added to the graph."""
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="XSS", description="Cross-site scripting")
        assert session.graph.get_node(hyp["id"]) is None

    def test_create_experiment(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="Test SQL injection")

        exp = session.create_experiment(
            hypothesis_id=hyp["id"],
            description="Test login endpoint",
            procedure="Send SQLi payloads",
            expected_result="RCE",
        )
        assert exp is not None
        assert exp.id.startswith("exp-")
        assert exp.hypothesis_id == hyp["id"]
        assert exp.status.value == "planned"
        assert len(session.state.experiments) == 1

    def test_create_experiment_no_hypothesis(self) -> None:
        session = InvestigationSession.new("https://example.com")
        exp = session.create_experiment(
            hypothesis_id="hyp-nonexistent",
            description="Test",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp is None

    def test_record_result(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="Test", description="Test")
        exp = session.create_experiment(
            hypothesis_id=hyp["id"],
            description="Test",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp is not None

        result = session.record_result(
            experiment_id=exp.id,
            status="completed",
            actual_result="Vulnerability confirmed",
        )
        assert result is True
        updated = [e for e in session.state.experiments if e.id == exp.id][0]
        assert updated.status.value == "completed"
        assert updated.actual_result == "Vulnerability confirmed"

    def test_record_result_no_experiment(self) -> None:
        session = InvestigationSession.new("https://example.com")
        result = session.record_result(
            experiment_id="exp-nonexistent",
            status="completed",
            actual_result="x",
        )
        assert result is False

    def test_create_pivot(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="Test", description="Test")
        exp = session.create_experiment(
            hypothesis_id=hyp["id"],
            description="Test",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp is not None

        pvt = session.create_pivot(
            description="Try SQL injection instead",
            rationale="XSS not found, check SQLi",
            reason="hypothesis_refuted",
            source_experiment_id=exp.id,
        )
        assert pvt.id.startswith("pvt-")
        assert pvt.source_experiment_id == exp.id
        assert len(session.state.pivots) == 1

    def test_create_finding(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        exp = session.create_experiment(
            hypothesis_id=hyp["id"],
            description="Test",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp is not None
        session.record_result(experiment_id=exp.id, status="completed", actual_result="Found SQLi")

        fnd = session.create_finding(
            title="SQL Injection Found",
            hypothesis_id=hyp["id"],
            description="SQL injection in login",
            bug_classes=["SQL_INJECTION"],
            severity="high",
            experiment_ids=[exp.id],
        )
        assert fnd.id.startswith("fnd-")
        assert fnd.severity.value == "high"
        assert len(session.state.findings) == 1

    def test_create_finding_updates_hypothesis(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="SQLi", description="SQL injection")
        exp = session.create_experiment(
            hypothesis_id=hyp["id"],
            description="Test",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp is not None
        session.record_result(experiment_id=exp.id, status="completed", actual_result="Found")

        fnd = session.create_finding(
            title="SQLi Found",
            hypothesis_id=hyp["id"],
            description="Found",
            bug_classes=["SQL_INJECTION"],
            severity="high",
            experiment_ids=[exp.id],
        )
        updated_hyp = [h for h in session.state.hypotheses if h["id"] == hyp["id"]][0]
        assert updated_hyp["finding_id"] == fnd.id

    def test_update_confidence_no_experiments(self) -> None:
        session = InvestigationSession.new("https://example.com")
        hyp = session.create_hypothesis(title="Test", description="Test")
        session.update_hypothesis_confidence(hyp["id"])
        hyp_updated = [h for h in session.state.hypotheses if h["id"] == hyp["id"]][0]
        assert hyp_updated.get("confidence", 0) >= 0

    def test_update_confidence_with_evidence(self) -> None:
        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation("other", description="Suspicious")
        hyp = session.create_hypothesis(
            title="Test", description="Test", observation_ids=[obs.id],
        )
        session.add_evidence(observation_id=obs.id, content="Evidence", source="test")
        hyp["observation_ids"] = [obs.id]
        # The evidence_ids have to be linked too
        ev = [e for e in session.state.evidence if e.observation_id == obs.id]
        if ev:
            hyp["evidence_ids"] = [e.id for e in ev]

        session.update_hypothesis_confidence(hyp["id"])
        hyp_updated = [h for h in session.state.hypotheses if h["id"] == hyp["id"]][0]
        assert hyp_updated.get("confidence", 0) > 0

    def test_update_confidence_unknown_hypothesis(self) -> None:
        session = InvestigationSession.new("https://example.com")
        with pytest.raises(ValueError):
            session.update_hypothesis_confidence("hyp-nonexistent")

    def test_receive_skos(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.receive_skos(["sko-1", "sko-2"])
        assert sorted(session.investigation.sko_ids) == ["sko-1", "sko-2"]

    def test_get_summary(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.create_observation("other", description="Obs 1")
        hyp = session.create_hypothesis(title="Hyp 1", description="Desc")
        exp = session.create_experiment(
            hypothesis_id=hyp["id"],
            description="Exp 1",
            procedure="Proc",
            expected_result="Res",
        )
        assert exp is not None
        session.record_result(experiment_id=exp.id, status="completed", actual_result="Found")

        summary = session.get_summary()
        assert "1 observations" in summary
        assert "1 hypotheses" in summary
        assert "1 experiments" in summary

    def test_graph_built_on_create(self) -> None:
        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation("other", description="Suspicious")
        hyp = session.create_hypothesis(title="SQLi", description="SQLi", observation_ids=[obs.id])
        exp = session.create_experiment(hypothesis_id=hyp["id"], description="Test", procedure="P", expected_result="R")
        assert exp is not None
        session.record_result(experiment_id=exp.id, status="completed", actual_result="Found")
        pvt = session.create_pivot(description="Pivot", rationale="R", reason="other", source_experiment_id=exp.id)
        fnd = session.create_finding(title="F", hypothesis_id=hyp["id"], description="D", bug_classes=[], severity="high", experiment_ids=[exp.id])

        graph = session.graph
        assert graph.get_node(obs.id) is not None
        assert graph.get_node(exp.id) is not None
        assert graph.get_node(pvt.id) is not None
        assert graph.get_node(fnd.id) is not None
        # Hypothesis is a dict, not in the graph
        assert graph.get_node(hyp["id"]) is None

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "session.json"
        session = InvestigationSession.new("https://example.com")
        session.save(str(nested))
        assert nested.exists()

    def test_event_fired_on_observation_create(self) -> None:
        session = InvestigationSession.new("https://example.com")
        received = []

        session.events.subscribe(ObservationCreatedEvent, lambda e: received.append(e))
        session.create_observation("other", description="Test")
        assert len(received) == 1

    def test_event_fired_on_hypothesis_create(self) -> None:
        session = InvestigationSession.new("https://example.com")
        received = []

        session.events.subscribe(HypothesisCreatedEvent, lambda e: received.append(e))
        session.create_hypothesis(title="Test", description="Test")
        assert len(received) == 1

    def test_target_set_in_state(self) -> None:
        session = InvestigationSession.new("https://example.com")
        assert session.investigation.target == "https://example.com"
        assert session.state.target == "https://example.com"
