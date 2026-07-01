"""Tests for investigation models."""
from __future__ import annotations

import pytest

from deephunter.investigation.models import (
    EvidenceRecord,
    EvidenceType,
    InvestigationReport,
    InvestigationSessionState,
    InvestigationStatus,
    ManualNote,
    ScopeEntry,
    ScopeEntryType,
    ScopeInfo,
    Task,
    TaskCategory,
    TaskPriority,
    TaskStatus,
    WorkflowDefinition,
    WorkflowResult,
    WorkflowStepDefinition,
    WorkflowStepResult,
    WorkflowStepType,
)


class TestTask:
    def test_defaults(self) -> None:
        t = Task(title="Test auth")
        assert t.title == "Test auth"
        assert t.status == TaskStatus.PENDING
        assert t.priority == TaskPriority.MEDIUM
        assert t.category == TaskCategory.OTHER
        assert t.id.startswith("task-")
        assert t.created_at is not None

    def test_complete(self) -> None:
        t = Task(title="Test")
        t.complete()
        assert t.status == TaskStatus.COMPLETED
        assert t.completed_at is not None

    def test_fail(self) -> None:
        t = Task(title="Test")
        t.fail("Timeout")
        assert t.status == TaskStatus.FAILED
        assert "Timeout" in t.notes

    def test_block(self) -> None:
        t = Task(title="Test")
        t.block("Missing API key")
        assert t.status == TaskStatus.BLOCKED

    @pytest.mark.parametrize("cat", list(TaskCategory))
    def test_all_categories(self, cat: TaskCategory) -> None:
        t = Task(title=cat.value, category=cat)
        assert t.category == cat


class TestScope:
    def test_scope_info_defaults(self) -> None:
        s = ScopeInfo(target="https://example.com")
        assert s.target == "https://example.com"
        assert s.entries == []
        assert s.technologies == []

    def test_scope_entry(self) -> None:
        e = ScopeEntry(value="https://example.com", entry_type=ScopeEntryType.IN_SCOPE)
        assert e.value == "https://example.com"
        assert e.entry_type == ScopeEntryType.IN_SCOPE


class TestEvidenceRecord:
    def test_defaults(self) -> None:
        ev = EvidenceRecord(title="Test evidence", content="Some data")
        assert ev.title == "Test evidence"
        assert ev.content == "Some data"
        assert ev.evidence_type == EvidenceType.OTHER
        assert ev.id.startswith("ev-")

    def test_to_dict(self) -> None:
        ev = EvidenceRecord(title="T", content="C", evidence_type=EvidenceType.HTTP_RESPONSE)
        d = ev.to_dict()
        assert d["title"] == "T"
        assert d["evidence_type"] == "http_response"


class TestManualNote:
    def test_defaults(self) -> None:
        n = ManualNote(content="Researcher observation")
        assert n.content == "Researcher observation"
        assert n.id.startswith("note-")


class TestInvestigationSessionState:
    def test_defaults(self) -> None:
        st = InvestigationSessionState()
        assert st.status == InvestigationStatus.CREATED
        assert st.session_id.startswith("inv-")
        assert st.tasks == []
        assert st.evidence == []

    def test_in_scope(self) -> None:
        st = InvestigationSessionState(
            target="https://example.com",
            scope=ScopeInfo(
                target="https://example.com",
                entries=[
                    ScopeEntry(value="https://example.com", entry_type=ScopeEntryType.IN_SCOPE),
                    ScopeEntry(value="https://out.com", entry_type=ScopeEntryType.OUT_OF_SCOPE),
                ],
            ),
        )
        assert len(st.in_scope) == 1
        assert st.in_scope[0].value == "https://example.com"
        assert len(st.out_of_scope) == 1

    def test_get_tasks_by_status(self) -> None:
        st = InvestigationSessionState()
        t1 = Task(title="A", status=TaskStatus.PENDING)
        t2 = Task(title="B", status=TaskStatus.COMPLETED)
        st.tasks = [t1, t2]
        assert len(st.get_tasks_by_status(TaskStatus.PENDING)) == 1
        assert len(st.get_tasks_by_status(TaskStatus.COMPLETED)) == 1

    def test_get_tasks_by_category(self) -> None:
        st = InvestigationSessionState()
        t1 = Task(title="A", category=TaskCategory.AUTHENTICATION)
        t2 = Task(title="B", category=TaskCategory.API)
        st.tasks = [t1, t2]
        assert len(st.get_tasks_by_category(TaskCategory.AUTHENTICATION)) == 1
        assert len(st.get_tasks_by_category(TaskCategory.API)) == 1


class TestWorkflowModels:
    def test_workflow_definition(self) -> None:
        step = WorkflowStepDefinition(id="step1", action="load_scope")
        wf = WorkflowDefinition(name="Test WF", steps=[step])
        assert wf.name == "Test WF"
        assert len(wf.steps) == 1
        assert wf.steps[0].id == "step1"

    def test_workflow_step_types(self) -> None:
        for st in WorkflowStepType:
            step = WorkflowStepDefinition(id="s1", step_type=st)
            assert step.step_type == st

    def test_workflow_step_result(self) -> None:
        r = WorkflowStepResult(step_id="s1", success=True, data={"key": "val"})
        assert r.success
        assert r.data["key"] == "val"

    def test_workflow_result(self) -> None:
        r = WorkflowResult(workflow_name="Test", success=True)
        assert r.success
        assert r.workflow_name == "Test"


class TestInvestigationReport:
    def test_defaults(self) -> None:
        report = InvestigationReport(title="Test Report", target="https://example.com")
        assert report.title == "Test Report"
        assert report.target == "https://example.com"
        assert report.evidence_summary == []
        assert report.open_questions == []

    def test_to_markdown(self) -> None:
        report = InvestigationReport(title="Test", target="https://example.com")
        md = report.to_markdown()
        assert "# Test" in md
        assert "**Target:** https://example.com" in md or "Target:" in md

    def test_to_markdown_with_evidence(self) -> None:
        report = InvestigationReport(
            title="Test",
            target="https://example.com",
            evidence_summary=[
                EvidenceRecord(title="Found XSS", content="<script>alert(1)</script>"),
            ],
            open_questions=["Is the WAF blocking?"],
            suggested_manual_tests=["Test reflected XSS"],
            draft_findings=[{"title": "XSS", "severity": "high", "description": "Reflected XSS in search"}],
        )
        md = report.to_markdown()
        assert "Found XSS" in md
        assert "Is the WAF blocking?" in md
        assert "Test reflected XSS" in md
        assert "XSS" in md
        assert "high" in md
