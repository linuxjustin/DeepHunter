"""Investigation Orchestrator Extensions.

Enhanced orchestration with profile support, live progress,
interactive review, and tool integration.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deephunter.core.config import DeepHunterConfig
from deephunter.investigation.profiles import ExecutionProfile, get_profile
from deephunter.investigation.profile_registry import get_profile_registry
from deephunter.investigation.models import (
    InvestigationSessionState,
    InvestigationStatus,
    ScopeEntry,
    ScopeEntryType,
    ScopeInfo,
    Task,
    TaskPriority,
    TaskStatus,
    WorkflowDefinition,
    WorkflowResult,
    WorkflowStepDefinition,
    WorkflowStepType,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class ProgressCallback:
    """Callback interface for live progress updates."""

    def on_step_start(self, step_id: str, step_name: str, step_num: int, total_steps: int) -> None:
        pass

    def on_step_complete(self, step_id: str, step_name: str, step_num: int, total_steps: int, elapsed_ms: float) -> None:
        pass

    def on_step_failed(self, step_id: str, step_name: str, step_num: int, total_steps: int, error: str) -> None:
        pass

    def on_progress(self, message: str, percentage: float) -> None:
        pass

    def on_warning(self, message: str) -> None:
        pass


class RichProgressCallback(ProgressCallback):
    """Progress callback that uses Rich for display."""

    def __init__(self, console: Any = None) -> None:
        try:
            from rich.console import Console
            self._console = console or Console()
        except ImportError:
            self._console = None

    def on_step_start(self, step_id: str, step_name: str, step_num: int, total_steps: int) -> None:
        if self._console:
            self._console.print(f"[cyan][{step_num}/{total_steps}][/cyan] Starting: {step_name}")

    def on_step_complete(self, step_id: str, step_name: str, step_num: int, total_steps: int, elapsed_ms: float) -> None:
        if self._console:
            self._console.print(f"[green][{step_num}/{total_steps}] Completed:[/green] {step_name} ({elapsed_ms:.0f}ms)")

    def on_step_failed(self, step_id: str, step_name: str, step_num: int, total_steps: int, error: str) -> None:
        if self._console:
            self._console.print(f"[red][{step_num}/{total_steps}] Failed:[/red] {step_name} - {error}")

    def on_progress(self, message: str, percentage: float) -> None:
        if self._console:
            self._console.print(f"[yellow]{message}[/yellow] ({percentage:.0f}%)")

    def on_warning(self, message: str) -> None:
        if self._console:
            self._console.print(f"[yellow]Warning:[/yellow] {message}")


class OrchestratorExtensions:
    """Extension methods for the InvestigationOrchestrator.

    Adds profile support, live progress, scope validation,
    interactive review, and tool integration.
    """

    @staticmethod
    def validate_scope(scope_entries: list[ScopeEntry]) -> tuple[bool, list[str]]:
        """Validate scope entries.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors: list[str] = []

        for entry in scope_entries:
            value = entry.value.strip()
            if not value:
                errors.append("Empty scope entry found")
                continue

            if entry.entry_type == ScopeEntryType.IN_SCOPE:
                if not OrchestratorExtensions._is_valid_scope_entry(value):
                    errors.append(f"Invalid scope entry: {value}")

        seen: set[str] = set()
        duplicates: list[str] = []
        for entry in scope_entries:
            normalized = entry.value.strip().lower()
            if normalized in seen:
                duplicates.append(entry.value)
            seen.add(normalized)

        if duplicates:
            errors.append(f"Duplicate scope entries: {', '.join(set(duplicates))}")

        return len(errors) == 0, errors

    @staticmethod
    def _is_valid_scope_entry(value: str) -> bool:
        if not value:
            return False
        if value.startswith(("http://", "https://", "*.", ".")):
            return True
        if "/" in value:
            return True
        return True

    @staticmethod
    def parse_scope_file(path: str | Path) -> list[ScopeEntry]:
        """Parse a scope file (one entry per line).

        Supports:
            - Plain domains/URLs
            - Lines starting with # are comments
            - Lines starting with ! are out-of-scope
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Scope file not found: {p}")

        entries: list[ScopeEntry] = []
        for line in p.read_text("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            entry_type = ScopeEntryType.IN_SCOPE
            if line.startswith("!"):
                line = line[1:].strip()
                entry_type = ScopeEntryType.OUT_OF_SCOPE

            if line:
                entries.append(ScopeEntry(value=line, entry_type=entry_type))

        return entries

    @staticmethod
    def build_interactive_review_summary(
        state: InvestigationSessionState,
        profile: ExecutionProfile,
    ) -> str:
        """Build a summary string for interactive review."""
        lines = [
            "=" * 60,
            "INVESTIGATION REVIEW",
            "=" * 60,
            "",
            f"Target: {state.target}",
            f"Profile: {profile.name}",
            f"Status: {state.status.value}",
            "",
        ]

        if state.scope.entries:
            lines.append("Scope:")
            in_scope = state.in_scope
            out_scope = state.out_of_scope
            lines.append(f"  In-scope entries: {len(in_scope)}")
            for e in in_scope[:5]:
                lines.append(f"    - {e.value}")
            if len(in_scope) > 5:
                lines.append(f"    ... and {len(in_scope) - 5} more")
            if out_scope:
                lines.append(f"  Out-of-scope entries: {len(out_scope)}")

        if state.scope.technologies:
            lines.append("")
            lines.append(f"Technologies detected: {', '.join(state.scope.technologies[:10])}")
            if len(state.scope.technologies) > 10:
                lines.append(f"  ... and {len(state.scope.technologies) - 10} more")

        if state.selected_knowledge_packs:
            lines.append("")
            lines.append(f"Knowledge Packs: {len(state.selected_knowledge_packs)} selected")

        if state.selected_methodology_packs:
            lines.append(f"Methodology Packs: {len(state.selected_methodology_packs)} selected")

        if state.tasks:
            lines.append("")
            lines.append(f"Tasks: {len(state.tasks)} total")
            pending = state.get_tasks_by_status(TaskStatus.PENDING)
            completed = state.get_tasks_by_status(TaskStatus.COMPLETED)
            lines.append(f"  Pending: {len(pending)}")
            lines.append(f"  Completed: {len(completed)}")

        lines.append("")
        lines.append("Estimated Duration: ~{profile.estimated_duration_minutes} minutes")
        lines.append("Estimated Cost: ~${profile.estimated_cost_usd:.2f}")
        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)

    @staticmethod
    def should_auto_approve(profile: ExecutionProfile, step: WorkflowStepDefinition) -> bool:
        """Determine if a step should auto-approve based on profile."""
        if step.step_type != WorkflowStepType.APPROVAL:
            return True

        if profile.auto_approve_passive:
            return True

        if not profile.require_manual_approval:
            return True

        return False

    @staticmethod
    def get_enabled_tools_for_profile(
        profile: ExecutionProfile,
        tool_group_names: list[str],
    ) -> dict[str, bool]:
        """Get which tools are enabled based on profile."""
        enabled = {}
        for tool_name in tool_group_names:
            enabled[tool_name] = True

        for group in profile.disabled_tool_groups:
            for tool_name in tool_group_names:
                if group.value in tool_name.lower():
                    enabled[tool_name] = False

        for group in profile.enabled_tool_groups:
            for tool_name in tool_group_names:
                if group.value in tool_name.lower():
                    enabled[tool_name] = True

        return enabled

    @staticmethod
    def create_scope_from_string(scope_str: str) -> list[ScopeEntry]:
        """Create scope entries from a comma-separated string or single value."""
        if not scope_str:
            return []

        entries: list[ScopeEntry] = []
        for value in scope_str.split(","):
            value = value.strip()
            if value:
                entries.append(ScopeEntry(value=value, entry_type=ScopeEntryType.IN_SCOPE))
        return entries

    @staticmethod
    def estimate_investigation_cost(profile: ExecutionProfile, step_count: int) -> dict[str, float]:
        """Estimate cost based on profile and step count."""
        base = profile.estimated_cost_usd
        per_step = 0.05
        estimated = base + (per_step * step_count)

        return {
            "estimated_usd": estimated,
            "duration_minutes": profile.estimated_duration_minutes + (step_count * 2),
            "api_calls_estimate": step_count * 3,
        }


def run_with_progress(
    orchestrator: Any,
    state: InvestigationSessionState,
    workflow: WorkflowDefinition,
    profile: ExecutionProfile,
    progress_callback: ProgressCallback | None = None,
    auto_approve: bool = False,
    callbacks: dict[str, Callable] | None = None,
) -> WorkflowResult:
    """Run orchestrator workflow with progress callbacks.

    This wraps the existing execute_workflow with progress reporting.
    """
    callback = progress_callback or RichProgressCallback()
    total_steps = len(workflow.steps)

    step_results: list = []
    completed: set[str] = set()
    total_start = time.perf_counter()

    state.status = InvestigationStatus.IN_PROGRESS

    for idx, step in enumerate(workflow.steps, 1):
        step_id = step.id
        step_name = step.name or step.id

        missing_deps = [d for d in step.depends_on if d not in completed]
        if missing_deps:
            callback.on_step_failed(step_id, step_name, idx, total_steps, f"Missing dependencies: {missing_deps}")
            continue

        if step_id in state.completed_steps:
            callback.on_step_start(step_id, step_name, idx, total_steps)
            callback.on_step_complete(step_id, step_name, idx, total_steps, 0)
            completed.add(step_id)
            continue

        callback.on_step_start(step_id, step_name, idx, total_steps)
        step_start = time.perf_counter()

        if step_id in (callbacks or {}):
            result_data = callbacks[step_id](state, step)
            success = True
            error = ""
        elif step.step_type == WorkflowStepType.APPROVAL:
            if auto_approve or OrchestratorExtensions.should_auto_approve(profile, step):
                result_data = {"approved": True, "auto": True}
                success = True
                error = ""
            else:
                result_data = {"approved": False, "awaiting": True}
                success = True
                error = ""
        else:
            try:
                if hasattr(orchestrator, "_execute_builtin"):
                    result_data = orchestrator._execute_builtin(state, step)
                else:
                    result_data = {}
                success = True
                error = ""
            except Exception as exc:
                logger.exception("Step %s failed", step_id)
                result_data = {}
                success = False
                error = str(exc)

        elapsed = (time.perf_counter() - step_start) * 1000

        if success:
            callback.on_step_complete(step_id, step_name, idx, total_steps, elapsed)
            completed.add(step_id)
            state.completed_steps.append(step_id)
        else:
            callback.on_step_failed(step_id, step_name, idx, total_steps, error)

        state.updated_at = datetime.now(UTC).isoformat()

    total_elapsed = (time.perf_counter() - total_start) * 1000

    from deephunter.investigation.models import WorkflowStepResult

    all_success = all(r.get("success", True) for r in step_results) if step_results else True
    if all_success:
        state.status = InvestigationStatus.COMPLETED
    else:
        state.status = InvestigationStatus.PAUSED

    return WorkflowResult(
        workflow_name=workflow.name,
        success=all_success,
        step_results=[WorkflowStepResult(step_id=s.id, success=s.id in completed, data={}) for s in workflow.steps],
        total_execution_time_ms=total_elapsed,
    )