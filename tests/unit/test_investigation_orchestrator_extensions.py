"""Unit tests for investigation orchestrator extensions."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from deephunter.investigation.models import (
    InvestigationSessionState,
    InvestigationStatus,
    ScopeEntry,
    ScopeEntryType,
    ScopeInfo,
)
from deephunter.investigation.orchestrator_extensions import (
    OrchestratorExtensions,
    RichProgressCallback,
    ProgressCallback,
)
from deephunter.investigation.profiles import (
    PASSIVE_PROFILE,
    BUGBOUNTY_PROFILE,
)


class TestOrchestratorExtensions:
    def test_validate_scope_valid_entries(self) -> None:
        entries = [
            ScopeEntry(value="https://example.com"),
            ScopeEntry(value="*.example.com"),
            ScopeEntry(value="https://api.example.com"),
        ]
        is_valid, errors = OrchestratorExtensions.validate_scope(entries)
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_scope_empty_entry(self) -> None:
        entries = [
            ScopeEntry(value="https://example.com"),
            ScopeEntry(value=""),
        ]
        is_valid, errors = OrchestratorExtensions.validate_scope(entries)
        assert is_valid is False
        assert any("Empty scope entry" in e for e in errors)

    def test_validate_scope_duplicates(self) -> None:
        entries = [
            ScopeEntry(value="https://example.com"),
            ScopeEntry(value="https://example.com"),
            ScopeEntry(value="HTTPS://EXAMPLE.COM"),
        ]
        is_valid, errors = OrchestratorExtensions.validate_scope(entries)
        assert is_valid is False
        assert any("Duplicate" in e for e in errors)

    def test_parse_scope_file(self, tmp_path: Path) -> None:
        content = """
# This is a comment
https://example.com
*.api.example.com
!https://out-of-scope.example.com
        """
        f = tmp_path / "scope.txt"
        f.write_text(content)

        entries = OrchestratorExtensions.parse_scope_file(f)
        assert len(entries) == 3
        assert entries[0].value == "https://example.com"
        assert entries[0].entry_type == ScopeEntryType.IN_SCOPE
        assert entries[1].value == "*.api.example.com"
        assert entries[2].value == "https://out-of-scope.example.com"
        assert entries[2].entry_type == ScopeEntryType.OUT_OF_SCOPE

    def test_parse_scope_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            OrchestratorExtensions.parse_scope_file("/nonexistent/scope.txt")

    def test_build_interactive_review_summary(self) -> None:
        state = InvestigationSessionState(
            target="https://example.com",
            scope=ScopeInfo(
                target="https://example.com",
                entries=[
                    ScopeEntry(value="https://example.com"),
                    ScopeEntry(value="*.example.com"),
                ],
                technologies=["Laravel", "PHP"],
            ),
        )

        summary = OrchestratorExtensions.build_interactive_review_summary(state, BUGBOUNTY_PROFILE)
        assert "https://example.com" in summary
        assert BUGBOUNTY_PROFILE.name in summary
        assert "Laravel" in summary

    def test_should_auto_approve_passive_profile(self) -> None:
        from deephunter.investigation.models import WorkflowStepDefinition, WorkflowStepType

        step = WorkflowStepDefinition(id="test", step_type=WorkflowStepType.APPROVAL)
        assert OrchestratorExtensions.should_auto_approve(PASSIVE_PROFILE, step) is True

    def test_should_not_auto_approve_bugbounty(self) -> None:
        from deephunter.investigation.models import WorkflowStepDefinition, WorkflowStepType

        step = WorkflowStepDefinition(id="test", step_type=WorkflowStepType.APPROVAL)
        assert OrchestratorExtensions.should_auto_approve(BUGBOUNTY_PROFILE, step) is False

    def test_should_auto_approve_non_approval_step(self) -> None:
        from deephunter.investigation.models import WorkflowStepDefinition, WorkflowStepType

        step = WorkflowStepDefinition(id="test", step_type=WorkflowStepType.BUILTIN, action="load_scope")
        assert OrchestratorExtensions.should_auto_approve(BUGBOUNTY_PROFILE, step) is True

    def test_create_scope_from_string(self) -> None:
        scope_str = "example.com, *.api.example.com, https://app.example.com"
        entries = OrchestratorExtensions.create_scope_from_string(scope_str)
        assert len(entries) == 3
        assert all(e.entry_type == ScopeEntryType.IN_SCOPE for e in entries)

    def test_create_scope_from_empty_string(self) -> None:
        entries = OrchestratorExtensions.create_scope_from_string("")
        assert len(entries) == 0

    def test_estimate_investigation_cost(self) -> None:
        cost = OrchestratorExtensions.estimate_investigation_cost(PASSIVE_PROFILE, step_count=5)
        assert "estimated_usd" in cost
        assert "duration_minutes" in cost
        assert "api_calls_estimate" in cost
        assert cost["estimated_usd"] == PASSIVE_PROFILE.estimated_cost_usd + (5 * 0.05)


class TestRichProgressCallback:
    def test_callback_creation(self) -> None:
        callback = RichProgressCallback()
        assert isinstance(callback, ProgressCallback)

    def test_callback_step_start(self, capsys: pytest.CaptureFixture) -> None:
        callback = RichProgressCallback()
        callback.on_step_start("load_scope", "Load Scope", 1, 5)
        captured = capsys.readouterr()
        assert "Load Scope" in captured.out

    def test_callback_step_complete(self, capsys: pytest.CaptureFixture) -> None:
        callback = RichProgressCallback()
        callback.on_step_complete("load_scope", "Load Scope", 1, 5, 100.0)
        captured = capsys.readouterr()
        assert "Completed" in captured.out

    def test_callback_step_failed(self, capsys: pytest.CaptureFixture) -> None:
        callback = RichProgressCallback()
        callback.on_step_failed("test_step", "Test Step", 1, 5, "Some error")
        captured = capsys.readouterr()
        assert "Failed" in captured.out
        assert "Some error" in captured.out

    def test_callback_progress(self, capsys: pytest.CaptureFixture) -> None:
        callback = RichProgressCallback()
        callback.on_progress("Processing...", 50.0)
        captured = capsys.readouterr()
        assert "Processing" in captured.out
        assert "50" in captured.out

    def test_callback_warning(self, capsys: pytest.CaptureFixture) -> None:
        callback = RichProgressCallback()
        callback.on_warning("This is a warning")
        captured = capsys.readouterr()
        assert "Warning" in captured.out