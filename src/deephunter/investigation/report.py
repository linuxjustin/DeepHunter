"""Investigation Report Generator.

Composes a structured ``InvestigationReport`` from the current investigation
state, including tasks, evidence, scope, and findings.

Integrates with the existing ``ReportGenerationWorkflow`` for AI-assisted
report drafting.
"""

from __future__ import annotations

from typing import Any

from deephunter.investigation.models import (
    EvidenceRecord,
    InvestigationReport,
    InvestigationSessionState,
    TaskPriority,
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
        failed_tasks = self._state.get_tasks_by_status(TaskStatus.FAILED)
        pending_tasks = self._state.get_tasks_by_status(TaskStatus.PENDING)

        report = InvestigationReport(
            title=f"Bug Bounty Investigation Report: {self._state.name or self._state.target}",
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
        pending = len(self._state.get_tasks_by_status(TaskStatus.PENDING))
        evidence_count = len(self._state.evidence)
        evidence_by_type = self._count_evidence_by_type()
        draft_findings = self._build_draft_findings()

        lines = [
            f"This report documents the security investigation of **{self._state.target}** performed using DeepHunter.",
            "",
            f"**Investigation Status:** {self._state.status.value}",
            f"**Session ID:** {self._state.session_id}",
            "",
            "### Key Metrics",
        ]

        metrics = [
            ("Tasks Completed", f"{completed}/{total}"),
            ("Tasks Failed", str(failed)),
            ("Tasks Pending", str(pending)),
            ("Evidence Records", str(evidence_count)),
            ("Draft Findings", str(len(draft_findings))),
        ]
        for label, value in metrics:
            lines.append(f"- **{label}:** {value}")

        if evidence_by_type:
            lines.append("")
            lines.append("**Evidence by Type:**")
            for ev_type, count in sorted(evidence_by_type.items(), key=lambda x: -x[1]):
                lines.append(f"  - {ev_type}: {count}")

        critical_findings = [f for f in draft_findings if f.get("severity") == "critical"]
        high_findings = [f for f in draft_findings if f.get("severity") == "high"]
        medium_findings = [f for f in draft_findings if f.get("severity") == "medium"]

        if critical_findings or high_findings:
            lines.append("")
            lines.append("### Priority Findings")
            if critical_findings:
                lines.append(f"- **{len(critical_findings)} Critical** finding(s) require immediate attention")
            if high_findings:
                lines.append(f"- **{len(high_findings)} High** severity finding(s) require attention")

        lines.append("")
        lines.append(f"This investigation used {len(self._state.selected_knowledge_packs)} knowledge packs "
                    f"and {len(self._state.selected_methodology_packs)} methodology packs.")

        return "\n".join(lines)

    def _count_evidence_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ev in self._state.evidence:
            counts[ev.evidence_type.value] = counts.get(ev.evidence_type.value, 0) + 1
        return counts

    def _build_scope_summary(self) -> str:
        if not self._state.scope.target:
            return "No scope defined."
        in_scope = self._state.in_scope
        out_scope = self._state.out_of_scope
        parts = [f"**Primary Target:** {self._state.scope.target}"]
        if in_scope:
            parts.append(f"\n### In Scope ({len(in_scope)} entries)")
            for e in in_scope:
                parts.append(f"- `{e.value}`")
        if out_scope:
            parts.append(f"\n### Out of Scope ({len(out_scope)} entries)")
            for e in out_scope[:10]:
                parts.append(f"- `{e.value}`")
            if len(out_scope) > 10:
                parts.append(f"- ... and {len(out_scope) - 10} more")
        if self._state.scope.technologies:
            parts.append(f"\n### Technologies Detected")
            parts.append(f"{', '.join(self._state.scope.technologies)}")
        return "\n".join(parts)

    def _build_recon_summary(self) -> str:
        recon_evidence = [
            ev for ev in self._state.evidence
            if ev.evidence_type.value in ("recon_artifact", "http_response", "observation")
        ]
        if not recon_evidence:
            return "No reconnaissance data collected during this investigation."
        parts = [f"**Total Recon Artifacts:** {len(recon_evidence)}"]

        hosts = [ev for ev in recon_evidence if "host" in ev.tags or "endpoint" in ev.tags]
        urls = [ev for ev in recon_evidence if "url" in ev.tags or "endpoint" in ev.content.lower()]
        technologies = [ev for ev in recon_evidence if "technology" in ev.tags]

        if hosts:
            parts.append(f"\n**Hosts/Endpoints:** {len(hosts)} discovered")
        if urls:
            parts.append(f"\n**URLs Analyzed:** {len(urls)}")
        if technologies:
            parts.append(f"\n**Technologies Identified:** {len(technologies)}")

        parts.append("\n### Sample Findings")
        for ev in recon_evidence[:5]:
            content_preview = ev.content[:150].replace("\n", " ")
            parts.append(f"- **{ev.title}**: {content_preview}...")

        if len(recon_evidence) > 5:
            parts.append(f"\n_... and {len(recon_evidence) - 5} more artifacts_")

        return "\n".join(parts)

    def _build_technology_profile(self) -> str:
        techs = self._state.scope.technologies
        if not techs:
            return "No technologies were identified during this investigation."
        parts = ["### Identified Technologies\n"]
        parts.append(", ".join(f"`{t}`" for t in techs))
        return "\n".join(parts)

    def _build_attack_surface_summary(self) -> str:
        endpoint_evidence = self._state.evidence
        if not endpoint_evidence:
            return "No attack surface data was collected during this investigation."
        task_count = len(self._state.tasks)
        ev_count = len(endpoint_evidence)

        parts = [
            f"**Total Evidence Records:** {ev_count}",
            f"**Total Tasks:** {task_count}",
            "",
        ]

        by_category: dict[str, int] = {}
        for ev in endpoint_evidence:
            by_category[ev.evidence_type.value] = by_category.get(ev.evidence_type.value, 0) + 1

        if by_category:
            parts.append("### Evidence by Category")
            for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
                parts.append(f"- **{cat}:** {count}")

        tasks_by_cat: dict[str, list] = {}
        for task in self._state.tasks:
            tasks_by_cat.setdefault(task.category.value, []).append(task)

        if tasks_by_cat:
            parts.append("\n### Tasks by Category")
            for cat, tasks in sorted(tasks_by_cat.items()):
                completed = sum(1 for t in tasks if t.status == TaskStatus.COMPLETED)
                parts.append(f"- **{cat}:** {completed}/{len(tasks)} completed")

        return "\n".join(parts)

    def _build_methodology_summary(self) -> str:
        parts = []
        if self._state.selected_knowledge_packs:
            parts.append("### Knowledge Packs Applied")
            for pack in self._state.selected_knowledge_packs:
                parts.append(f"- `{pack}`")
        if self._state.selected_methodology_packs:
            parts.append("\n### Methodology Packs Applied")
            for pack in self._state.selected_methodology_packs:
                parts.append(f"- `{pack}`")
        if not parts:
            return "No methodology packs were selected for this investigation."
        return "\n".join(parts)

    def _build_timeline(self) -> str:
        parts = [
            f"| Event | Details |",
            f"|--------|---------|",
            f"| Investigation Started | {self._state.created_at} |",
            f"| Current Status | {self._state.status.value} |",
            f"| Last Updated | {self._state.updated_at} |",
            f"| Session ID | {self._state.session_id} |",
        ]
        if self._state.completed_steps:
            parts.append(f"| Steps Completed | {len(self._state.completed_steps)} |")
            for step in self._state.completed_steps[-5:]:
                parts.append(f"|   - {step} | completed |")

        parts.extend([
            "",
            f"| Tasks Total | {len(self._state.tasks)} |",
            f"| Tasks Completed | {len(self._state.get_tasks_by_status(TaskStatus.COMPLETED))} |",
            f"| Tasks Failed | {len(self._state.get_tasks_by_status(TaskStatus.FAILED))} |",
            f"| Tasks Pending | {len(self._state.get_tasks_by_status(TaskStatus.PENDING))} |",
        ])
        return "\n".join(parts)

    def _build_open_questions(self) -> list[str]:
        questions: list[str] = []
        blocked = self._state.get_tasks_by_status(TaskStatus.BLOCKED)
        for task in blocked:
            questions.append(f"**BLOCKED:** {task.title} - {task.notes or 'No notes'}")
        pending = self._state.get_tasks_by_status(TaskStatus.PENDING)
        for task in pending:
            priority_icon = "🔴" if task.priority == TaskPriority.CRITICAL else "🟡" if task.priority == TaskPriority.HIGH else "🟢"
            questions.append(f"{priority_icon} **[{task.priority.value.upper()}]** {task.title} ({task.category.value})")
        return questions

    def _build_suggested_manual_tests(self) -> list[str]:
        tests: list[str] = []
        pending = self._state.get_tasks_by_status(TaskStatus.PENDING)
        for task in pending:
            priority_icon = "🔴" if task.priority == TaskPriority.CRITICAL else "🟡" if task.priority == TaskPriority.HIGH else "🟢"
            tests.append(f"{priority_icon} **[{task.priority.value.upper()}]** {task.title}")
            if task.description:
                tests.append(f"  - {task.description[:100]}")
        return tests

    def _build_draft_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        completed = self._state.get_tasks_by_status(TaskStatus.COMPLETED)
        for task in completed:
            task_evidence = [ev for ev in self._state.evidence if ev.source_task == task.id]
            severity = "info"
            if task.priority == TaskPriority.CRITICAL:
                severity = "critical"
            elif task.priority == TaskPriority.HIGH:
                severity = "high"
            elif task.priority == TaskPriority.MEDIUM:
                severity = "medium"
            elif task.priority == TaskPriority.LOW:
                severity = "low"

            finding = {
                "title": task.title,
                "description": task.description or f"Completed investigation of {task.category.value} attack surface",
                "severity": severity,
                "category": task.category.value,
                "evidence_count": len(task_evidence),
                "confidence": task.confidence or 0.5,
                "status": task.status.value,
                "completed_at": task.completed_at or "",
            }
            if task_evidence:
                finding["sample_evidence"] = task_evidence[0].content[:200]
            findings.append(finding)
        return findings

    def _build_references(self) -> list[str]:
        refs: list[str] = []
        for ev in self._state.evidence:
            if ev.evidence_type.value == "reference" and ev.content:
                refs.append(ev.content)
        if self._state.selected_knowledge_packs:
            refs.extend(self._state.selected_knowledge_packs)
        return refs
