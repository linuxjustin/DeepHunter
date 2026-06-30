"""Workflow engine for building investigation workflows.

Supports linear sequences and decision-point-based branching workflows.
"""

from __future__ import annotations

from deephunter.methodology.models import (
    Checklist,
    DecisionPoint,
    InvestigationBranch,
    InvestigationWorkflow,
    MethodologySelection,
    RiskCategory,
    WorkflowStep,
)
from deephunter.methodology.profiles import get_framework_profiles


def _build_linear_workflow(
    selection: MethodologySelection,
    name: str,
    description: str,
) -> InvestigationWorkflow:
    """Build a linear workflow from methodology objectives and techniques."""
    steps: list[WorkflowStep] = []
    for idx, obj in enumerate(selection.methodology.objectives):
        risk = RiskCategory.MEDIUM
        obj_lower = obj.name.lower()
        if any(kw in obj_lower for kw in ["rce", "sql", "deserialization", "ssti", "xxe"]):
            risk = RiskCategory.CRITICAL
        elif any(kw in obj_lower for kw in ["xss", "idor", "csrf", "ssrf", "privilege"]):
            risk = RiskCategory.HIGH

        steps.append(
            WorkflowStep(
                order=idx + 1,
                title=obj.name,
                description=obj.description,
                technique=f"Manual testing of {obj.name}",
                expected_findings=f"Potential {obj.name} vulnerabilities",
                risk=risk,
                estimated_time_minutes=45,
                tags=obj.tags,
            )
        )

    # Append technique-based steps
    for idx, tech in enumerate(selection.methodology.techniques):
        order = len(steps) + idx + 1
        steps.append(
            WorkflowStep(
                order=order,
                title=tech.name,
                description=tech.description,
                technique=tech.name,
                expected_findings=f"Results from {tech.name}",
                risk=tech.risk,
                estimated_time_minutes=30,
                tags=tech.tags,
            )
        )

    return InvestigationWorkflow(
        name=name or f"{selection.methodology.name} Investigation Workflow",
        description=description or f"Step-by-step investigation workflow for {selection.methodology.name}",
        steps=steps,
    )


def _build_profiled_workflow(
    selection: MethodologySelection,
) -> InvestigationWorkflow | None:
    """Build a workflow enriched with framework profile details."""
    fp = get_framework_profiles().get(
        next(
            (f for f in selection.methodology.frameworks),
            "",
        )
    )
    if not fp:
        return None

    wf = _build_linear_workflow(
        selection,
        name=f"{fp.framework_name} Investigation Workflow",
        description=f"Security investigation workflow for {fp.framework_name}",
    )

    # Add framework-specific steps
    for idx, wf_name in enumerate(fp.testing_workflows):
        if wf_name not in [s.title for s in wf.steps]:
            wf.steps.append(
                WorkflowStep(
                    order=len(wf.steps) + 1,
                    title=wf_name,
                    description=wf_name,
                    technique=wf_name,
                    expected_findings=f"Findings from {wf_name}",
                    risk=RiskCategory.MEDIUM,
                    estimated_time_minutes=60,
                    tags=fp.tags,
                )
            )

    wf.steps.sort(key=lambda s: s.order)
    for i, step in enumerate(wf.steps):
        step.order = i + 1

    # Insert decision points if patterns suggest branching
    contradiction_keywords = [
        "contradict", "inconsistent", "unexpected", "anomaly",
        "different", "unusual",
    ]
    for step in wf.steps:
        if any(kw in step.title.lower() for kw in contradiction_keywords):
            wf.decision_points.append(
                DecisionPoint(
                    step_id=step.id,
                    question=f"Did you find something {step.title.lower()}?",
                    branches=[
                        InvestigationBranch(
                            condition="yes",
                            description="Escalate to deep dive",
                            next_step_ids=[],
                        ),
                        InvestigationBranch(
                            condition="no",
                            description="Continue with next step",
                            next_step_ids=[],
                        ),
                    ],
                )
            )

    return wf


class WorkflowEngine:
    """Builds investigation workflows from methodology selections and profiles."""

    def __init__(self) -> None:
        self._cache: dict[str, InvestigationWorkflow] = {}

    def build_workflows(
        self,
        selections: list[MethodologySelection],
        checklists: list[Checklist] | None = None,
    ) -> list[InvestigationWorkflow]:
        """Build workflows for each methodology selection."""
        workflows: list[InvestigationWorkflow] = []
        for selection in selections:
            wf = _build_profiled_workflow(selection)
            if wf is None:
                wf = _build_linear_workflow(
                    selection,
                    name=f"{selection.methodology.name} Workflow",
                    description=f"Workflow for {selection.methodology.name}",
                )
            workflows.append(wf)

        return workflows
