"""Tests for the Report Generator."""
from __future__ import annotations

from deephunter.investigation.models import (
    EvidenceRecord,
    EvidenceType,
    InvestigationSessionState,
    ScopeEntry,
    ScopeEntryType,
    ScopeInfo,
    Task,
    TaskCategory,
    TaskPriority,
    TaskStatus,
)
from deephunter.investigation.report import ReportGenerator


def _make_state(
    target: str = "https://example.com",
    tasks: list | None = None,
    evidence: list | None = None,
    technologies: list | None = None,
) -> InvestigationSessionState:
    return InvestigationSessionState(
        target=target,
        name="Test Investigation",
        scope=ScopeInfo(
            target=target,
            entries=[
                ScopeEntry(value=target, entry_type=ScopeEntryType.IN_SCOPE),
            ],
            technologies=technologies or ["node.js", "express"],
        ),
        tasks=tasks or [],
        evidence=evidence or [],
        selected_methodology_packs=["rest_api", "session"],
    )


class TestReportGenerator:
    def test_generate_empty(self) -> None:
        state = _make_state()
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "Test Investigation" in report.title
        assert report.target == "https://example.com"
        assert "Tasks Completed:" in report.executive_summary

    def test_generate_with_tasks(self) -> None:
        tasks = [
            Task(title="Auth review", category=TaskCategory.AUTHENTICATION, status=TaskStatus.COMPLETED),
            Task(title="XSS check", category=TaskCategory.XSS, status=TaskStatus.PENDING),
            Task(title="SQLi check", category=TaskCategory.SQL_INJECTION, status=TaskStatus.FAILED),
        ]
        state = _make_state(tasks=tasks)
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "**Tasks Completed:** 1/3" in report.executive_summary
        assert "**Tasks Failed:** 1" in report.executive_summary
        assert len(report.completed_tasks) == 1
        assert report.completed_tasks[0].title == "Auth review"

    def test_generate_with_evidence(self) -> None:
        evidence = [
            EvidenceRecord(title="XSS payload", content="<script>", evidence_type=EvidenceType.HTTP_RESPONSE),
            EvidenceRecord(title="Admin cookie", content="session=abc123", evidence_type=EvidenceType.COOKIE),
        ]
        state = _make_state(evidence=evidence)
        gen = ReportGenerator(state)
        report = gen.generate()
        assert len(report.evidence_summary) == 2

    def test_scope_summary(self) -> None:
        state = _make_state()
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "https://example.com" in report.scope_summary
        assert "In Scope" in report.scope_summary
        assert "node.js" in report.scope_summary

    def test_scope_summary_empty(self) -> None:
        state = InvestigationSessionState()
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "No scope defined" in report.scope_summary

    def test_technology_profile(self) -> None:
        state = _make_state(technologies=["aws", "lambda", "s3"])
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "aws" in report.technology_profile
        assert "lambda" in report.technology_profile
        assert "s3" in report.technology_profile

    def test_open_questions(self) -> None:
        tasks = [
            Task(title="Auth", status=TaskStatus.BLOCKED, notes="Need credentials"),
            Task(title="API", status=TaskStatus.PENDING),
        ]
        state = _make_state(tasks=tasks)
        gen = ReportGenerator(state)
        report = gen.generate()
        assert len(report.open_questions) >= 1
        assert any("Need credentials" in q for q in report.open_questions)

    def test_suggested_manual_tests(self) -> None:
        tasks = [
            Task(title="XSS Deep Dive", category=TaskCategory.XSS, priority=TaskPriority.HIGH, status=TaskStatus.PENDING),
        ]
        state = _make_state(tasks=tasks)
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "XSS Deep Dive" in report.suggested_manual_tests[0]

    def test_draft_findings(self) -> None:
        tasks = [
            Task(title="Reflected XSS", category=TaskCategory.XSS, priority=TaskPriority.HIGH, status=TaskStatus.COMPLETED),
        ]
        state = _make_state(tasks=tasks)
        gen = ReportGenerator(state)
        report = gen.generate()
        assert len(report.draft_findings) == 1
        assert report.draft_findings[0]["title"] == "Reflected XSS"
        assert report.draft_findings[0]["severity"] == "high"

    def test_methodology_summary(self) -> None:
        state = _make_state()
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "rest_api" in report.methodology_applied
        assert "session" in report.methodology_applied

    def test_timeline(self) -> None:
        state = _make_state()
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "Investigation Started" in report.timeline
        assert "created" in report.timeline

    def test_references(self) -> None:
        evidence = [
            EvidenceRecord(title="Ref", content="https://example.com/docs", evidence_type=EvidenceType.REFERENCE),
        ]
        state = _make_state(evidence=evidence)
        gen = ReportGenerator(state)
        report = gen.generate()
        assert "https://example.com/docs" in report.references

    def test_to_markdown(self) -> None:
        state = _make_state()
        gen = ReportGenerator(state)
        report = gen.generate()
        md = report.to_markdown()
        assert "Investigation Report" in md
        assert "Executive Summary" in md
        assert "Scope" in md
        assert "Reconnaissance Summary" in md
        assert "Technology Profile" in md
        assert "Attack Surface Summary" in md
        assert "Methodology Applied" in md
        assert "Investigation Timeline" in md
        assert "Evidence Collected" in md
        assert "Open Questions" in md
        assert "Suggested Manual Tests" in md
        assert "Draft Findings" in md
