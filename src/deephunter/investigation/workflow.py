"""Workflow DSL — YAML-driven workflow definitions.

Supports loading workflow definitions from YAML files, validating them,
and providing them to the orchestrator for execution.

Workflows are provider-independent and can be created without modifying code.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from deephunter.investigation.models import (
    WorkflowDefinition,
    WorkflowStepDefinition,
    WorkflowStepType,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)

BUILTIN_ACTIONS: dict[str, str] = {
    "load_scope": "Load investigation scope from target definition",
    "import_recon": "Import reconnaissance data for in-scope assets",
    "normalize_recon": "Normalize and deduplicate recon data",
    "build_attack_surface_graph": "Build the attack surface graph from recon data",
    "identify_technologies": "Identify technologies from the attack surface",
    "select_knowledge_packs": "Select knowledge packs based on identified technologies",
    "select_methodology": "Select methodology packs for relevant bug classes",
    "generate_plan": "Generate an investigation plan using the Planner",
    "build_context": "Build context using the Context Engine",
    "execute_tasks": "Execute manual investigation tasks from the plan",
    "collect_evidence": "Collect and store structured evidence",
    "draft_report": "Draft the final investigation report",
    "review_findings": "Review and triage draft findings",
    "export_report": "Export the investigation report",
}

AI_TASK_TYPES: dict[str, str] = {
    "reasoning": "AI-assisted reasoning and analysis",
    "planning": "AI-assisted investigation planning",
    "report_drafting": "AI-assisted report drafting",
    "code_explanation": "AI-assisted code explanation",
    "checklist_expansion": "AI-assisted checklist expansion",
}


class WorkflowLoader:
    """Loads and validates YAML workflow definitions."""

    def __init__(self, workflow_dir: str | Path | None = None) -> None:
        self._workflow_dir = Path(workflow_dir) if workflow_dir else Path("workflows")

    def load(self, path: str | Path) -> WorkflowDefinition:
        """Load a single workflow from a YAML file.

        Args:
            path: Path to the workflow YAML file.

        Returns:
            A validated WorkflowDefinition.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the YAML is invalid or missing required fields.
        """
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Workflow file not found: {p}")

        raw = p.read_text("utf-8")
        return self._parse(raw, p)

    def load_by_name(self, name: str) -> WorkflowDefinition:
        """Load a workflow by name from the configured workflow directory.

        Searches for ``<name>.yaml`` or ``<name>.yml`` in the workflow directory.

        Args:
            name: The workflow name (without extension).

        Returns:
            A validated WorkflowDefinition.

        Raises:
            FileNotFoundError: If no matching file is found.
        """
        for ext in (".yaml", ".yml"):
            p = self._workflow_dir / f"{name}{ext}"
            if p.exists():
                return self._parse(p.read_text("utf-8"), p)
        raise FileNotFoundError(
            f"Workflow '{name}' not found in {self._workflow_dir} "
            f"(tried .yaml and .yml)"
        )

    def list_workflows(self) -> list[dict[str, str]]:
        """List available workflows in the workflow directory.

        Returns:
            A list of ``{name, path, description}`` dicts.
        """
        results: list[dict[str, str]] = []
        if not self._workflow_dir.exists():
            return results
        for f in sorted(self._workflow_dir.iterdir()):
            if f.suffix in (".yaml", ".yml"):
                try:
                    raw = f.read_text("utf-8")
                    data = yaml.safe_load(raw) or {}
                    results.append({
                        "name": f.stem,
                        "path": str(f),
                        "description": data.get("description", ""),
                    })
                except Exception as exc:
                    logger.warning("Failed to load workflow %s: %s", f, exc)
        return results

    def _parse(self, raw: str, source: Path) -> WorkflowDefinition:
        """Parse raw YAML string into a validated WorkflowDefinition."""
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {source}: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"Workflow {source} must be a YAML mapping")

        name = data.get("name", "")
        if not name:
            raise ValueError(f"Workflow {source} must have a 'name' field")

        steps_raw = data.get("steps", [])
        if not isinstance(steps_raw, list) or not steps_raw:
            raise ValueError(f"Workflow {source} must have at least one step")

        steps: list[WorkflowStepDefinition] = []
        for i, s in enumerate(steps_raw):
            if not isinstance(s, dict):
                raise ValueError(f"Step {i} in {source} must be a mapping")
            step_id = s.get("id", f"step_{i}")
            step_type_str = s.get("type", "builtin")
            try:
                step_type = WorkflowStepType(step_type_str)
            except ValueError:
                raise ValueError(
                    f"Step '{step_id}' in {source}: unknown type '{step_type_str}'. "
                    f"Valid types: {[t.value for t in WorkflowStepType]}"
                ) from None
            steps.append(WorkflowStepDefinition(
                id=step_id,
                name=s.get("name", step_id),
                description=s.get("description", ""),
                step_type=step_type,
                action=s.get("action", ""),
                task_type=s.get("task_type", ""),
                prompt_template=s.get("prompt_template", ""),
                depends_on=s.get("depends_on", []),
                condition=s.get("condition", ""),
                branches=s.get("branches", {}),
                sub_workflow=s.get("sub_workflow", ""),
                approval_message=s.get("approval_message", ""),
                timeout_seconds=s.get("timeout_seconds", 300),
                retry_count=s.get("retry_count", 0),
                config=s.get("config", {}),
            ))

        return WorkflowDefinition(
            name=name,
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            steps=steps,
            tags=data.get("tags", []),
            config=data.get("config", {}),
        )


class WorkflowStepHandler:
    """Resolves and validates builtin actions and AI task types.

    Provides metadata about available actions/tasks without executing them.
    """

    @staticmethod
    def is_valid_builtin_action(action: str) -> bool:
        return action in BUILTIN_ACTIONS

    @staticmethod
    def get_builtin_action_description(action: str) -> str:
        return BUILTIN_ACTIONS.get(action, "Unknown action")

    @staticmethod
    def is_valid_ai_task_type(task_type: str) -> bool:
        return task_type in AI_TASK_TYPES

    @staticmethod
    def list_builtin_actions() -> list[str]:
        return list(BUILTIN_ACTIONS.keys())

    @staticmethod
    def list_ai_task_types() -> list[str]:
        return list(AI_TASK_TYPES.keys())
