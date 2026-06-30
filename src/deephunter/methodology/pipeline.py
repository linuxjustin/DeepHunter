"""Methodology pipeline — orchestrates the full methodology lifecycle.

Stages:
  1. Load framework profiles
  2. Select matching methodologies
  3. Generate checklists
  4. Build investigation workflows
  5. Generate manual tests
  6. Produce MethodologyResult
"""

from __future__ import annotations

from deephunter.methodology.checklist import ChecklistEngine
from deephunter.methodology.events import (
    ChecklistGeneratedEvent,
    MethodologyCompletedEvent,
    MethodologyEventBus,
    MethodologySelectedEvent,
    MethodologyStartedEvent,
    WorkflowBuiltEvent,
)
from deephunter.methodology.models import (
    FrameworkProfile,
    ManualTest,
    MethodologyResult,
    MethodologySelection,
    RiskCategory,
)
from deephunter.methodology.profiles import get_framework_profiles
from deephunter.methodology.selector import MethodologySelector
from deephunter.methodology.workflow import WorkflowEngine


class MethodologyPipeline:
    """Orchestrates the methodology lifecycle.

    Usage:
        pipeline = MethodologyPipeline()
        result = pipeline.run(
            technologies=['Python', 'PostgreSQL'],
            frameworks=['Django'],
            attack_surface_areas=['authentication', 'api'],
        )
    """

    def __init__(
        self,
        selector: MethodologySelector | None = None,
        checklist_engine: ChecklistEngine | None = None,
        workflow_engine: WorkflowEngine | None = None,
        event_bus: MethodologyEventBus | None = None,
    ) -> None:
        self.selector = selector or MethodologySelector()
        self.checklist_engine = checklist_engine or ChecklistEngine()
        self.workflow_engine = workflow_engine or WorkflowEngine()
        self.event_bus = event_bus or MethodologyEventBus()

    def run(
        self,
        technologies: list[str] | None = None,
        frameworks: list[str] | None = None,
        attack_surface_areas: list[str] | None = None,
    ) -> MethodologyResult:
        """Execute the methodology pipeline.

        Args:
            technologies: List of detected technology names.
            frameworks: List of detected framework names.
            attack_surface_areas: List of identified attack surface areas.

        Returns:
            MethodologyResult with selections, checklists, workflows, and manual tests.
        """
        self.event_bus.emit(MethodologyStartedEvent(data={"technologies": technologies or [], "frameworks": frameworks or []}))

        # Stage 1: Load framework profiles
        profiles = list(get_framework_profiles().values())
        self.event_bus.emit(MethodologyStartedEvent(data={"stage": "profiles_loaded", "count": len(profiles)}))

        # Stage 2: Select methodology
        selections = self.selector.select(
            technologies=technologies,
            frameworks=frameworks,
            attack_surface_areas=attack_surface_areas,
        )
        self.event_bus.emit(MethodologySelectedEvent(data={"selections": len(selections)}))

        # Stage 3: Generate checklists
        checklists = self.checklist_engine.generate(
            selections=selections,
            framework_profiles=profiles,
            attack_surface_areas=attack_surface_areas,
        )
        self.event_bus.emit(ChecklistGeneratedEvent(data={"checklists": len(checklists)}))

        # Stage 4: Build workflows
        workflows = self.workflow_engine.build_workflows(
            selections=selections,
            checklists=checklists,
        )
        self.event_bus.emit(WorkflowBuiltEvent(data={"workflows": len(workflows)}))

        # Stage 5: Generate manual tests from checklist items
        manual_tests = self._generate_manual_tests(selections, checklists)

        # Stage 6: Assemble result
        result = MethodologyResult(
            selections=selections,
            checklists=checklists,
            workflows=workflows,
            manual_tests=manual_tests,
            framework_profiles=profiles,
            total_selected=len(selections),
            total_checklist_items=sum(cl.total_items for cl in checklists),
            total_workflow_steps=sum(len(wf.steps) for wf in workflows),
        )

        self.event_bus.emit(MethodologyCompletedEvent(data={"result_id": result.id}))
        return result

    def _generate_manual_tests(
        self,
        selections: list[MethodologySelection],
        checklists: list[Checklist],
    ) -> list[ManualTest]:
        """Generate ManualTest objects from checklist items."""
        tests: list[ManualTest] = []
        for cl in checklists:
            selection = next(
                (s for s in selections if s.methodology.id == cl.methodology_id),
                None,
            )
            for item in cl.items:
                risk = RiskCategory.MEDIUM
                obj_lower = item.objective.lower()
                if any(
                    kw in obj_lower
                    for kw in [
                        "rce", "sql injection", "deserialization", "ssti",
                        "remote code", "unserialize",
                    ]
                ):
                    risk = RiskCategory.CRITICAL
                elif any(kw in obj_lower for kw in ["xss", "idor", "csrf", "ssrf", "privilege"]):
                    risk = RiskCategory.HIGH

                manual_test = ManualTest(
                    description=item.objective,
                    procedure=item.procedure,
                    expected_result=item.expected_outcome,
                    priority=(
                        1.0
                        if item.priority.value == "critical"
                        else 0.8 if item.priority.value == "high"
                        else 0.5 if item.priority.value == "medium"
                        else 0.2
                    ),
                    estimated_effort_hours=0.75,
                    methodology_id=cl.methodology_id,
                    checklist_item_id=item.id,
                    framework_profile_id=(
                        selection.matched_frameworks[0] if selection and selection.matched_frameworks else ""
                    ),
                    risk=risk,
                )
                tests.append(manual_test)

        return tests
