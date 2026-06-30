"""Professional Bug Bounty Workflow Library.

Production-ready investigation workflows encoding expert bug bounty methodology.
Supports phase-based execution, conditional branching, template reuse,
variable resolution, checkpoint management, and real-time metrics.

Composes existing subsystems without adding new architectural layers.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import yaml

from deephunter.core.exceptions import InvestigationError
from deephunter.investigation.models import (
    ConditionalPhase,
    InvestigationSessionState,
    InvestigationStatus,
    PhaseMetrics,
    PhaseStep,
    Task,
    TaskCategory,
    TaskPriority,
    TaskStatus,
    WorkflowCheckpoint,
    WorkflowDefinition,
    WorkflowMetrics,
    WorkflowPhase,
    WorkflowResult,
    WorkflowStepDefinition,
    WorkflowStepResult,
    WorkflowStepType,
    WorkflowTemplate,
    WorkflowVariable,
    WorkflowVariableType,
    WorkflowVariables,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class TemplateCompiler:
    """Compiles YAML templates and variables into executable workflow steps.

    Resolves ``{{ variable }}`` references, expands template phases,
    and produces a flat list of WorkflowStepDefinitions.
    """

    def __init__(self, templates: list[WorkflowTemplate] | None = None) -> None:
        self._templates: dict[str, WorkflowTemplate] = {}
        if templates:
            for t in templates:
                self._templates[t.name] = t

    def register_template(self, template: WorkflowTemplate) -> None:
        self._templates[template.name] = template

    def load_template_yaml(self, path: str | Path) -> WorkflowTemplate:
        p = Path(path).expanduser().resolve()
        raw = p.read_text("utf-8")
        data = yaml.safe_load(raw)
        return WorkflowTemplate(**data)

    def compile_phase(
        self,
        phase: WorkflowPhase,
        variables: WorkflowVariables,
    ) -> list[WorkflowStepDefinition]:
        """Compile a phase into executable step definitions."""
        steps: list[WorkflowStepDefinition] = []
        for ps in phase.steps:
            resolved = self._resolve_step(ps, variables)
            steps.append(resolved)
        return steps

    def compile_phases(
        self,
        phases: list[WorkflowPhase],
        variables: WorkflowVariables,
    ) -> list[WorkflowStepDefinition]:
        steps: list[WorkflowStepDefinition] = []
        for phase in phases:
            steps.extend(self.compile_phase(phase, variables))
        return steps

    def _resolve_step(
        self,
        ps: PhaseStep,
        variables: WorkflowVariables,
    ) -> WorkflowStepDefinition:
        prompt = ps.prompt_template
        if prompt:
            prompt = self._resolve_string(prompt, variables)

        config = dict(ps.config)
        for k, v in config.items():
            if isinstance(v, str):
                config[k] = self._resolve_string(v, variables)

        return WorkflowStepDefinition(
            id=ps.id,
            name=self._resolve_string(ps.name, variables),
            description=self._resolve_string(ps.description, variables),
            step_type=ps.step_type,
            action=ps.action,
            task_type=ps.task_type,
            prompt_template=prompt,
            depends_on=list(ps.depends_on),
            condition=ps.condition,
            branches=dict(ps.branches),
            approval_message=self._resolve_string(ps.approval_message, variables),
            timeout_seconds=ps.timeout_seconds,
            retry_count=ps.retry_count,
            config=config,
        )

    @staticmethod
    def _resolve_string(text: str, variables: WorkflowVariables) -> str:
        if "{{" not in text:
            return text
        result = text
        vars_dict = {
            "target": variables.extra.get("target", ""),
            "framework": variables.framework,
            "cloud_provider": variables.cloud_provider,
            "auth_method": variables.auth_method,
            "graphql_enabled": str(variables.graphql_enabled).lower(),
            "api_present": str(variables.api_present).lower(),
            "websocket_enabled": str(variables.websocket_enabled).lower(),
            "sso_enabled": str(variables.sso_enabled).lower(),
            "admin_panel_detected": str(variables.admin_panel_detected).lower(),
            "planner_confidence": str(variables.planner_confidence),
        }
        for key, val in vars_dict.items():
            result = result.replace("{{ " + key + " }}", val)
            result = result.replace("{{" + key + "}}", val)
        return result


class ConditionEvaluator:
    """Evaluates workflow conditions against session state and variables."""

    @staticmethod
    def evaluate(condition: str, state: InvestigationSessionState) -> bool:
        if not condition:
            return True

        if condition == "has_tasks":
            return len(state.tasks) > 0
        if condition == "has_evidence":
            return len(state.evidence) > 0
        if condition == "has_findings":
            return len(state.get_tasks_by_status(TaskStatus.COMPLETED)) > 0
        if condition == "has_recon":
            return state.status.value >= InvestigationStatus.RECON_COMPLETED.value
        if condition == "has_technologies":
            return len(state.variables.technologies) > 0

        if condition.startswith("framework:"):
            expected = condition.split(":", 1)[1].strip()
            return state.variables.framework.lower() == expected.lower()

        if condition.startswith("technology:"):
            expected = condition.split(":", 1)[1].strip()
            return any(expected.lower() in t.lower() for t in state.variables.technologies)

        if condition.startswith("cloud:"):
            expected = condition.split(":", 1)[1].strip()
            return state.variables.cloud_provider.lower() == expected.lower()

        if condition.startswith("variable:"):
            rest = condition.split(":", 1)[1].strip()
            if "=" in rest:
                key, val = rest.split("=", 1)
                return str(state.variables.extra.get(key.strip(), "")).lower() == val.strip().lower()
            return bool(state.variables.extra.get(rest))

        if condition == "graphql_enabled":
            return state.variables.graphql_enabled
        if condition == "api_present":
            return state.variables.api_present
        if condition == "websocket_enabled":
            return state.variables.websocket_enabled
        if condition == "sso_enabled":
            return state.variables.sso_enabled
        if condition == "admin_panel_detected":
            return state.variables.admin_panel_detected

        return False


class WorkflowMetricsTracker:
    """Tracks real-time metrics for a running workflow."""

    def __init__(self) -> None:
        self._metrics = WorkflowMetrics()
        self._phase_times: dict[str, float] = {}

    @property
    def metrics(self) -> WorkflowMetrics:
        return self._metrics

    def initialize(self, phases: list[WorkflowPhase]) -> None:
        self._metrics.total_phases = len(phases)
        self._metrics.completed_phases = 0
        total_steps = 0
        total_minutes = 0.0

        for phase in phases:
            pm = PhaseMetrics(phase_id=phase.id)
            pm.total_steps = len(phase.steps)
            pm.completed_steps = 0
            phase_minutes = sum(s.estimated_time_minutes for s in phase.steps)
            pm.estimated_minutes = phase_minutes
            pm.evidence_required = sum(1 for er in phase.evidence_requirements if er.required)

            total_steps += pm.total_steps
            total_minutes += phase_minutes
            self._metrics.phase_metrics[phase.id] = pm

        self._metrics.total_steps = total_steps
        self._metrics.estimated_remaining_minutes = total_minutes

    def complete_step(self, phase_id: str, step_id: str) -> None:
        pm = self._metrics.phase_metrics.get(phase_id)
        if pm:
            pm.completed_steps += 1
            pm.completion_pct = (pm.completed_steps / pm.total_steps * 100) if pm.total_steps > 0 else 100.0
        self._metrics.completed_steps += 1
        self._recalculate()

    def complete_phase(self, phase_id: str) -> None:
        self._metrics.completed_phases += 1
        pm = self._metrics.phase_metrics.get(phase_id)
        if pm:
            pm.completed_steps = pm.total_steps
            pm.completion_pct = 100.0
        self._recalculate()

    def record_evidence(self, count: int = 1) -> None:
        self._metrics.evidence_count += count
        self._recalculate()

    def set_planner_confidence(self, confidence: float) -> None:
        self._metrics.planner_confidence = confidence

    def set_outstanding_tasks(self, count: int) -> None:
        self._metrics.outstanding_tasks = count

    def _recalculate(self) -> None:
        total_required = sum(
            pm.evidence_required for pm in self._metrics.phase_metrics.values()
        )
        if total_required > 0:
            self._metrics.evidence_coverage = min(
                100.0, (self._metrics.evidence_count / total_required) * 100
            )

        total_checklist = sum(pm.total_steps for pm in self._metrics.phase_metrics.values())
        if total_checklist > 0:
            self._metrics.checklist_coverage = (
                self._metrics.completed_steps / total_checklist * 100
            )

        total_estimated = sum(
            pm.estimated_minutes for pm in self._metrics.phase_metrics.values()
        )
        completed_fraction = (
            self._metrics.completed_steps / self._metrics.total_steps
            if self._metrics.total_steps > 0
            else 0
        )
        self._metrics.estimated_remaining_minutes = total_estimated * (1 - completed_fraction)


class WorkflowLibrary:
    """Professional Bug Bounty Workflow Library.

    Loads, compiles, and resolves production investigation workflows.
    """

    def __init__(self, workflow_dir: str | Path | None = None) -> None:
        self._dir = Path(workflow_dir) if workflow_dir else Path("workflows/professional")
        self._templates: dict[str, WorkflowTemplate] = {}
        self._workflows: dict[str, WorkflowDefinition] = {}
        self._compiler = TemplateCompiler()

    @property
    def compiler(self) -> TemplateCompiler:
        return self._compiler

    # ── Template loading ──────────────────────────────────────────────────

    def load_templates(self) -> dict[str, WorkflowTemplate]:
        template_dir = self._dir / "templates"
        if not template_dir.exists():
            return {}
        for f in sorted(template_dir.iterdir()):
            if f.suffix in (".yaml", ".yml"):
                try:
                    raw = f.read_text("utf-8")
                    data = yaml.safe_load(raw)
                    t = WorkflowTemplate(**data)
                    self._templates[t.name] = t
                    self._compiler.register_template(t)
                except Exception as exc:
                    logger.warning("Failed to load template %s: %s", f, exc)
        return self._templates

    def get_template(self, name: str) -> WorkflowTemplate | None:
        return self._templates.get(name)

    def expand_template(self, template_name: str, variables: WorkflowVariables) -> list[WorkflowStepDefinition]:
        template = self._templates.get(template_name)
        if not template:
            raise InvestigationError(f"Template not found: {template_name}")
        return self._compiler.compile_phases(template.phases, variables)

    # ── Workflow loading ──────────────────────────────────────────────────

    def load_all(self) -> dict[str, WorkflowDefinition]:
        self.load_templates()
        for subdir in ["core", "framework"]:
            wf_dir = self._dir / subdir
            if not wf_dir.exists():
                continue
            for f in sorted(wf_dir.iterdir()):
                if f.suffix in (".yaml", ".yml"):
                    try:
                        wf = self._load_single(f)
                        self._workflows[wf.name] = wf
                    except Exception as exc:
                        logger.warning("Failed to load workflow %s: %s", f, exc)
        return self._workflows

    def load_by_name(self, name: str) -> WorkflowDefinition:
        if name in self._workflows:
            return self._workflows[name]
        for subdir in ["core", "framework"]:
            for ext in (".yaml", ".yml"):
                p = self._dir / subdir / f"{name}{ext}"
                if p.exists():
                    wf = self._load_single(p)
                    self._workflows[wf.name] = wf
                    return wf
        raise FileNotFoundError(f"Workflow '{name}' not found in {self._dir}")

    def load_by_technology(self, tech: str) -> list[WorkflowDefinition]:
        results: list[WorkflowDefinition] = []
        for wf in self._workflows.values():
            tags = [t.lower() for t in wf.tags]
            if tech.lower() in tags:
                results.append(wf)
        return results

    def list_workflows(self) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        for name, wf in self._workflows.items():
            results.append({
                "name": name,
                "description": wf.description[:80],
                "phases": str(len(wf.phases)),
                "tags": ", ".join(wf.tags),
            })
        return sorted(results, key=lambda x: x["name"])

    def list_core_workflows(self) -> list[dict[str, str]]:
        return [w for w in self.list_workflows() if any(
            w["name"] == c for c in [
                "initial_recon", "attack_surface", "technology_profiling",
                "authentication_review", "authorization_review", "session_management",
                "business_logic", "rest_api", "graphql", "javascript",
                "cloud_review", "file_upload", "websocket", "sso_review",
                "admin_panel", "finding_prep", "report_generation",
            ]
        )]

    def list_framework_workflows(self) -> list[dict[str, str]]:
        core_names = {w["name"] for w in self.list_core_workflows()}
        return [w for w in self.list_workflows() if w["name"] not in core_names]

    def _load_single(self, path: Path) -> WorkflowDefinition:
        raw = path.read_text("utf-8")
        data = yaml.safe_load(raw)
        if not data or "name" not in data:
            raise ValueError(f"Workflow {path} must have a 'name' field")

        phases_raw = data.pop("phases", [])
        conditional_raw = data.pop("conditional_phases", [])
        templates_raw = data.pop("templates", [])
        variables_raw = data.pop("variables", [])
        checkpoints_raw = data.pop("checkpoints", [])

        phases = [WorkflowPhase(**p) for p in phases_raw]
        conditional_phases = [ConditionalPhase(**cp) for cp in conditional_raw]
        templates = [WorkflowTemplate(**t) for t in templates_raw]
        variables = [WorkflowVariable(**v) for v in variables_raw]
        checkpoints = [WorkflowCheckpoint(**c) for c in checkpoints_raw]

        steps_raw = data.pop("steps", [])
        steps = [WorkflowStepDefinition(**s) for s in steps_raw] if steps_raw else []

        return WorkflowDefinition(
            name=data["name"],
            description=data.get("description", ""),
            version=str(data.get("version", "1.0")),
            steps=steps,
            phases=phases,
            conditional_phases=conditional_phases,
            templates=templates,
            variables=variables,
            checkpoints=checkpoints,
            tags=data.get("tags", []),
            config=data.get("config", {}),
        )

    # ── Phase selection ───────────────────────────────────────────────────

    def select_phases(
        self,
        workflow: WorkflowDefinition,
        state: InvestigationSessionState,
    ) -> list[WorkflowPhase]:
        """Select applicable phases, evaluating conditional phases."""
        selected: list[WorkflowPhase] = list(workflow.phases)
        for cp in workflow.conditional_phases:
            if self._evaluate_condition(cp, state):
                selected.append(cp.phase)
        return selected

    def _evaluate_condition(self, cp: ConditionalPhase, state: InvestigationSessionState) -> bool:
        if cp.framework_match and state.variables.framework.lower() in [f.lower() for f in cp.framework_match]:
            return True
        if cp.technology_match:
            for tm in cp.technology_match:
                if any(tm.lower() in t.lower() for t in state.variables.technologies):
                    return True
        if cp.condition and ConditionEvaluator.evaluate(cp.condition, state):
            return True
        if cp.variable_match:
            for key, val in cp.variable_match.items():
                if str(state.variables.extra.get(key, "")).lower() == str(val).lower():
                    return True
        return False

    # ── Metrics ───────────────────────────────────────────────────────────

    def build_metrics(
        self,
        phases: list[WorkflowPhase],
        completed_phases: list[str],
        completed_steps: list[str],
        evidence_count: int,
        planner_confidence: float = 0.0,
    ) -> WorkflowMetrics:
        tracker = WorkflowMetricsTracker()
        tracker.initialize(phases)
        tracker._metrics.evidence_count = evidence_count
        tracker._metrics.planner_confidence = planner_confidence
        tracker._metrics.completed_phases = len(completed_phases)

        for phase in phases:
            if phase.id in completed_phases:
                tracker.complete_phase(phase.id)
            pm = tracker._metrics.phase_metrics.get(phase.id)
            if pm:
                pm.completed_steps = pm.total_steps if phase.id in completed_phases else 0
                pm.completion_pct = 100.0 if phase.id in completed_phases else 0.0

        total_checklist = sum(pm.total_steps for pm in tracker._metrics.phase_metrics.values())
        if total_checklist > 0:
            tracker._metrics.checklist_coverage = (
                len(completed_steps) / total_checklist * 100
            )
        tracker._metrics.completed_steps = len(completed_steps)

        return tracker.metrics
