"""Tests for the Evidence Manager."""
from __future__ import annotations

import pytest

from deephunter.investigation.evidence import EvidenceManager
from deephunter.investigation.models import (
    EvidenceType,
    InvestigationSessionState,
    ScopeInfo,
)


@pytest.fixture
def state() -> InvestigationSessionState:
    return InvestigationSessionState(
        target="https://example.com",
        scope=ScopeInfo(target="https://example.com"),
    )


@pytest.fixture
def manager(state: InvestigationSessionState) -> EvidenceManager:
    return EvidenceManager(state)


class TestEvidenceManager:
    def test_record_evidence(self, manager: EvidenceManager, state: InvestigationSessionState) -> None:
        ev = manager.record_evidence(
            title="Login page",
            content="200 OK on /login",
            evidence_type=EvidenceType.HTTP_RESPONSE,
            source_step="recon",
            tags=["login", "endpoint"],
        )
        assert ev.id.startswith("ev-")
        assert ev.title == "Login page"
        assert ev.evidence_type == EvidenceType.HTTP_RESPONSE
        assert ev.source_step == "recon"
        assert len(state.evidence) == 1

    def test_get_by_id(self, manager: EvidenceManager) -> None:
        ev = manager.record_evidence(title="T", content="C")
        found = manager.get_by_id(ev.id)
        assert found is not None
        assert found.id == ev.id

    def test_get_by_id_not_found(self, manager: EvidenceManager) -> None:
        assert manager.get_by_id("nonexistent") is None

    def test_get_by_type(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="A", content="C1", evidence_type=EvidenceType.HTTP_RESPONSE)
        manager.record_evidence(title="B", content="C2", evidence_type=EvidenceType.HTTP_RESPONSE)
        manager.record_evidence(title="C", content="C3", evidence_type=EvidenceType.MANUAL_NOTE)
        results = manager.get_by_type(EvidenceType.HTTP_RESPONSE)
        assert len(results) == 2
        results = manager.get_by_type(EvidenceType.MANUAL_NOTE)
        assert len(results) == 1

    def test_get_by_step(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="A", content="C1", source_step="step1")
        manager.record_evidence(title="B", content="C2", source_step="step1")
        manager.record_evidence(title="C", content="C3", source_step="step2")
        assert len(manager.get_by_step("step1")) == 2
        assert len(manager.get_by_step("step2")) == 1

    def test_get_by_task(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="A", content="C1", source_task="task1")
        assert len(manager.get_by_task("task1")) == 1

    def test_get_by_tag(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="A", content="C1", tags=["xss", "critical"])
        manager.record_evidence(title="B", content="C2", tags=["xss"])
        manager.record_evidence(title="C", content="C3", tags=["sqli"])
        assert len(manager.get_by_tag("xss")) == 2
        assert len(manager.get_by_tag("sqli")) == 1

    def test_search(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="XSS in search", content="<script>alert(1)</script>")
        manager.record_evidence(title="SQL injection", content="' OR '1'='1")
        assert len(manager.search("xss")) == 1
        assert len(manager.search("SQL")) == 1
        assert len(manager.search("alert")) == 1

    def test_count(self, manager: EvidenceManager) -> None:
        assert manager.count() == 0
        manager.record_evidence(title="A", content="C")
        assert manager.count() == 1

    def test_delete(self, manager: EvidenceManager) -> None:
        ev = manager.record_evidence(title="A", content="C")
        assert manager.count() == 1
        assert manager.delete(ev.id)
        assert manager.count() == 0

    def test_delete_not_found(self, manager: EvidenceManager) -> None:
        assert not manager.delete("nonexistent")

    def test_clear(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="A", content="C")
        manager.record_evidence(title="B", content="C")
        assert manager.count() == 2
        manager.clear()
        assert manager.count() == 0

    def test_export_all(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="A", content="C")
        exported = manager.export_all()
        assert len(exported) == 1
        assert exported[0]["title"] == "A"

    def test_summary(self, manager: EvidenceManager) -> None:
        manager.record_evidence(title="A", content="C", evidence_type=EvidenceType.HTTP_RESPONSE)
        manager.record_evidence(title="B", content="C", evidence_type=EvidenceType.OBSERVATION)
        manager.record_evidence(title="C", content="C", evidence_type=EvidenceType.HTTP_RESPONSE)
        summary = manager.summary()
        assert summary["http_response"] == 2
        assert summary["observation"] == 1
