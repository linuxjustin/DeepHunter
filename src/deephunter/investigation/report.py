"""Investigation Report Generator.

Composes a structured ``InvestigationReport`` from the current investigation
state, including tasks, evidence, scope, and findings.

Integrates with the existing ``ReportGenerationWorkflow`` for AI-assisted
report drafting.
"""

from __future__ import annotations

from typing import Any

from deephunter.investigation.models import (
    InvestigationReport,
    InvestigationSessionState,
    TaskStatus,
)


class ReportGenerator:
    """Generates structured investigation reports from session state.

    Usage:
        generator = ReportGenerator(state)
        report = generator.generate()
        markdown = report.to_markdown()
    """

    def __init__(self, state: InvestigationSessionState) -> None:
        self._state = state

    def generate(
        self,
        executive_summary: str = "",
        extra_findings: list[dict[str, Any]] | None = None,
    ) -> InvestigationReport:
        """Generate a complete investigation report.

        Args:
            executive_summary: Optional override for the executive summary.
            extra_findings: Optional list of finding dicts to include.

        Returns:
            A populated InvestigationReport.
        """
        completed_tasks = self._state.get_tasks_by_status(TaskStatus.COMPLETED)
        self._state.get_tasks_by_status(TaskStatus.FAILED)

        report = InvestigationReport(
            title=f"Investigation Report: {self._state.name or self._state.target}",
            target=self._state.target,
            executive_summary=executive_summary or self._build_executive_summary(),
            scope_summary=self._build_scope_summary(),
            recon_summary=self._build_recon_summary(),
            technology_profile=self._build_technology_profile(),
            attack_surface_summary=self._build_attack_surface_summary(),
            methodology_applied=self._build_methodology_summary(),
            timeline=self._build_timeline(),
            evidence_summary=self._state.evidence,
            open_questions=self._build_open_questions(),
            suggested_manual_tests=self._build_suggested_manual_tests(),
            draft_findings=extra_findings or self._build_draft_findings(),
            references=self._build_references(),
            completed_tasks=completed_tasks,
        )
        return report

    def _build_executive_summary(self) -> str:
        total = len(self._state.tasks)
        completed = len(self._state.get_tasks_by_status(TaskStatus.COMPLETED))
        failed = len(self._state.get_tasks_by_status(TaskStatus.FAILED))
        evidence_count = len(self._state.evidence)
        findings_count = 0
        return (
            f"Investigation of {self._state.target} completed "
            f"({completed}/{total} tasks done, {failed} failed, "
            f"{evidence_count} evidence records collected, "
            f"{findings_count} draft findings)."
        )

    def _build_scope_summary(self) -> str:
        if not self._state.scope.target:
            return "No scope defined."
        in_scope = self._state.in_scope
        out_scope = self._state.out_of_scope
        parts = [f"**Target:** {self._state.scope.target}"]
        if in_scope:
            parts.append(f"\n**In Scope ({len(in_scope)}):**")
            for e in in_scope:
                parts.append(f"- {e.value}")
        if out_scope:
            parts.append(f"\n**Out of Scope ({len(out_scope)}):**")
            for e in out_scope:
                parts.append(f"- {e.value}")
        if self._state.scope.technologies:
            parts.append(f"\n**Technologies:** {', '.join(self._state.scope.technologies)}")
        return "\n".join(parts)

    def _build_recon_summary(self) -> str:
        recon_evidence = [
            ev for ev in self._state.evidence
            if ev.evidence_type.value in ("recon_artifact", "http_response", "observation")
        ]
        if not recon_evidence:
            return "No reconnaissance data collected."
        parts = [f"**Recon Artifacts:** {len(recon_evidence)}"]
        for ev in recon_evidence[:10]:
            parts.append(f"- {ev.title}: {ev.content[:100]}")
        if len(recon_evidence) > 10:
            parts.append(f"- ... and {len(recon_evidence) - 10} more")
        return "\n".join(parts)

    def _build_technology_profile(self) -> str:
        techs = self._state.scope.technologies
        if not techs:
            return "No technologies identified."
        return f"**Identified Technologies:** {', '.join(techs)}"

    def _build_attack_surface_summary(self) -> str:
        endpoint_evidence = self._state.evidence
        if not endpoint_evidence:
            return "No attack surface data collected."
        task_count = len(self._state.tasks)
        ev_count = len(endpoint_evidence)
        return f"**Observations collected:** {ev_count} evidence records across {task_count} tasks."

    def _build_methodology_summary(self) -> str:
        packs = self._state.selected_methodology_packs
        if not packs:
            return "No methodology packs selected."
        return f"**Selected Methodology Packs:** {', '.join(packs)}"

    def _build_timeline(self) -> str:
        parts = [f"Investigation started: {self._state.created_at}"]
        parts.append(f"Current status: {self._state.status.value}")
        parts.append(f"Steps completed: {len(self._state.completed_steps)}")
        parts.append(f"Tasks created: {len(self._state.tasks)}")
        return "\n".join(parts)

    def _build_open_questions(self) -> list[str]:
        questions: list[str] = []
        blocked = self._state.get_tasks_by_status(TaskStatus.BLOCKED)
        for task in blocked:
            questions.append(f"Task '{task.title}' is blocked: {task.notes}")
        pending = self._state.get_tasks_by_status(TaskStatus.PENDING)
        for task in pending:
            questions.append(f"Task '{task.title}' is pending ({task.category.value})")
        return questions

    def _build_suggested_manual_tests(self) -> list[str]:
        tests: list[str] = []
        pending = self._state.get_tasks_by_status(TaskStatus.PENDING)
        for task in pending:
            tests.append(f"[{task.priority.value}] {task.title} ({task.category.value})")
        return tests

    def _build_draft_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        completed = self._state.get_tasks_by_status(TaskStatus.COMPLETED)
        for task in completed:
            task_evidence = [ev for ev in self._state.evidence if ev.source_task == task.id]
            findings.append({
                "title": task.title,
                "description": task.description,
                "severity": task.priority.value,
                "category": task.category.value,
                "evidence_count": len(task_evidence),
                "confidence": task.confidence,
            })
        return findings

    def _build_references(self) -> list[str]:
        refs: list[str] = []
        for ev in self._state.evidence:
            if ev.evidence_type.value == "reference" and ev.content:
                refs.append(ev.content)
        if self._state.selected_knowledge_packs:
            refs.extend(self._state.selected_knowledge_packs)
        return refs
