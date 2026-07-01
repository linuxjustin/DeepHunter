"""Investigation Workflow Orchestrator.

Coordinates all existing DeepHunter subsystems into an end-to-end
investigation workflow.  Drives sequential execution, conditional
branching, manual approval points, checkpointing, and recovery.

Composes, does not replace: Planner, AgentOrchestratorV2, ModelRouter,
InvestigationSession, ContextEngine, KnowledgePackRegistry,
MethodologyEngine, and the Evaluation Framework.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deephunter.core.config import DeepHunterConfig
from deephunter.core.exceptions import InvestigationError
from deephunter.investigation.evidence import EvidenceManager
from deephunter.investigation.models import (
    EvidenceType,
    InvestigationReport,
    InvestigationSessionState,
    InvestigationStatus,
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
from deephunter.investigation.report import ReportGenerator
from deephunter.investigation.workflow import WorkflowLoader
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)

# Forward references for lazy imports to avoid circular deps at module level
_INVESTIGATION_SESSION_CLS = None
_PLANNER_CLS = None
_ORCHESTRATOR_V2_CLS = None
_MODEL_ROUTER_CLS = None
_CONTEXT_ENGINE_CLS = None
_KP_REGISTRY = None
_METHODOLOGY_PIPELINE_CLS = None


def _get_investigation_session():
    global _INVESTIGATION_SESSION_CLS
    if _INVESTIGATION_SESSION_CLS is None:
        from deephunter.reasoning.session import InvestigationSession
        _INVESTIGATION_SESSION_CLS = InvestigationSession
    return _INVESTIGATION_SESSION_CLS


def _get_planner():
    global _PLANNER_CLS
    if _PLANNER_CLS is None:
        from deephunter.planning import Planner
        _PLANNER_CLS = Planner
    return _PLANNER_CLS


def _get_orchestrator_v2():
    global _ORCHESTRATOR_V2_CLS
    if _ORCHESTRATOR_V2_CLS is None:
        from deephunter.agents.orchestrator_v2 import AgentOrchestratorV2
        _ORCHESTRATOR_V2_CLS = AgentOrchestratorV2
    return _ORCHESTRATOR_V2_CLS


def _get_model_router():
    global _MODEL_ROUTER_CLS
    if _MODEL_ROUTER_CLS is None:
        from deephunter.router import ModelRouter
        _MODEL_ROUTER_CLS = ModelRouter
    return _MODEL_ROUTER_CLS


def _get_context_engine():
    global _CONTEXT_ENGINE_CLS
    if _CONTEXT_ENGINE_CLS is None:
        from deephunter.context import ContextEngine
        _CONTEXT_ENGINE_CLS = ContextEngine
    return _CONTEXT_ENGINE_CLS


def _get_kp_registry():
    global _KP_REGISTRY
    if _KP_REGISTRY is None:
        from deephunter.knowledge import load_all_knowledge_packs
        _KP_REGISTRY = load_all_knowledge_packs()
    return _KP_REGISTRY


def _get_methodology_pipeline():
    global _METHODOLOGY_PIPELINE_CLS
    if _METHODOLOGY_PIPELINE_CLS is None:
        from deephunter.methodology import MethodologyPipeline
        _METHODOLOGY_PIPELINE_CLS = MethodologyPipeline
    return _METHODOLOGY_PIPELINE_CLS


class InvestigationOrchestrator:
    """Coordinates the full investigation workflow lifecycle.

    Usage::

        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")

        # Load a YAML workflow and execute it
        workflow = orch.load_workflow("workflows/web_app_review.yaml")
        result = orch.execute_workflow(state, workflow)

        # Or drive manually
        orch.load_scope(state, scope_data)
        orch.import_recon(state, recon_data)
        orch.generate_plan(state)
        orch.execute_tasks(state)
        report = orch.generate_report(state)
    """

    def __init__(
        self,
        config: DeepHunterConfig | None = None,
        workflow_dir: str | Path | None = None,
    ) -> None:
        self._config = config or DeepHunterConfig.default()
        self._workflow_loader = WorkflowLoader(workflow_dir or Path("workflows"))
        self._reasoning_sessions: dict[str, Any] = {}

    # ── Session Lifecycle ─────────────────────────────────────────────────────

    def create_session(
        self,
        target: str,
        name: str = "",
        scope_entries: list[ScopeEntry] | None = None,
        technologies: list[str] | None = None,
    ) -> InvestigationSessionState:
        """Create a new investigation session with a reasoning session.

        Args:
            target: The target being investigated.
            name: Optional human-readable name.
            scope_entries: Optional initial scope entries.
            technologies: Optional initial technology list.

        Returns:
            A new InvestigationSessionState.
        """
        state = InvestigationSessionState(
            target=target,
            name=name or f"Investigation: {target}",
            status=InvestigationStatus.CREATED,
            scope=ScopeInfo(
                target=target,
                entries=scope_entries or [
                    ScopeEntry(value=target, entry_type=ScopeEntryType.IN_SCOPE)
                ],
                technologies=technologies or [],
            ),
        )

        reasoning_cls = _get_investigation_session()
        reasoning_session = reasoning_cls.new(target=target, name=state.name)
        state.reasoning_session_id = reasoning_session.investigation.id
        self._reasoning_sessions[state.session_id] = reasoning_session

        return state

    def get_reasoning_session(self, state: InvestigationSessionState) -> Any:
        """Get the reasoning session associated with this investigation state."""
        return self._reasoning_sessions.get(state.session_id)

    def save_session(self, state: InvestigationSessionState, path: str | Path) -> Path:
        """Persist the full session state to JSON.

        Also saves the associated reasoning session.
        """
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)

        reasoning = self.get_reasoning_session(state)
        if reasoning:
            reasoning_path = p.parent / f"{p.stem}_reasoning{p.suffix}"
            reasoning.save(str(reasoning_path))

        data = state.model_dump()
        p.write_text(
            __import__("json").dumps(data, indent=2, default=str),
            "utf-8",
        )
        logger.debug("Saved investigation session %s to %s", state.session_id, p)
        return p

    def load_session(self, path: str | Path) -> InvestigationSessionState:
        """Restore a session state from JSON."""
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Session file not found: {p}")

        data = __import__("json").loads(p.read_text("utf-8"))
        state = InvestigationSessionState(**data)

        reasoning_path = p.parent / f"{p.stem}_reasoning{p.suffix}"
        if reasoning_path.exists():
            reasoning_cls = _get_investigation_session()
            reasoning = reasoning_cls.load(str(reasoning_path))
            self._reasoning_sessions[state.session_id] = reasoning

        return state

    # ── Workflow Loading ─────────────────────────────────────────────────────

    def load_workflow(self, path: str | Path) -> WorkflowDefinition:
        """Load a workflow definition from a YAML file."""
        return self._workflow_loader.load(path)

    def load_workflow_by_name(self, name: str) -> WorkflowDefinition:
        """Load a workflow by name from the configured workflow directory."""
        return self._workflow_loader.load_by_name(name)

    def list_workflows(self) -> list[dict[str, str]]:
        """List available workflows."""
        return self._workflow_loader.list_workflows()

    # ── Workflow Execution ───────────────────────────────────────────────────

    def execute_workflow(
        self,
        state: InvestigationSessionState,
        workflow: WorkflowDefinition,
        auto_approve: bool = False,
        callbacks: dict[str, Callable] | None = None,
        progress_callback: "ProgressCallback | None" = None,
    ) -> WorkflowResult:
        """Execute a complete workflow definition against the given session.

        Args:
            state: The investigation session state.
            workflow: The workflow definition to execute.
            auto_approve: If True, automatically approve all approval steps.
            callbacks: Optional dict of step_id -> callable for custom handlers.

        Returns:
            A WorkflowResult with per-step results.
        """
        step_results: list[WorkflowStepResult] = []
        total_start = time.perf_counter()
        total_steps = len(workflow.steps)

        state.status = InvestigationStatus.IN_PROGRESS

        completed: set[str] = set()

        for idx, step in enumerate(workflow.steps, 1):
            step_name = step.name or step.action or step.id
            if progress_callback:
                progress_callback.on_step_start(step.id, step_name, idx, total_steps)

            # Check dependencies
            missing_deps = [d for d in step.depends_on if d not in completed]
            if missing_deps:
                step_results.append(WorkflowStepResult(
                    step_id=step.id,
                    success=False,
                    error=f"Dependencies not satisfied: {', '.join(missing_deps)}",
                ))
                if progress_callback:
                    progress_callback.on_step_failed(step.id, step_name, idx, total_steps, "Missing dependencies")
                continue

            # Check if we should skip (checkpoint recovery)
            if step.id in state.completed_steps:
                logger.info("Skipping already completed step: %s", step.id)
                step_results.append(WorkflowStepResult(
                    step_id=step.id, success=True, data={"skipped": True},
                ))
                completed.add(step.id)
                if progress_callback:
                    progress_callback.on_step_complete(step.id, step_name, idx, total_steps, 0)
                continue

            # Execute step
            state.current_step = step.id
            step_start = time.perf_counter()

            try:
                if step.id in (callbacks or {}):
                    result_data = callbacks[step.id](state, step)
                    success = True
                    error = ""

                elif step.step_type == WorkflowStepType.BUILTIN:
                    if not step.action:
                        result_data = {}
                        success = True
                        error = ""
                    else:
                        result_data = self._execute_builtin(state, step)
                        success = True
                        error = ""

                elif step.step_type == WorkflowStepType.AI:
                    result_data = self._execute_ai_step(state, step)
                    success = True
                    error = ""

                elif step.step_type == WorkflowStepType.APPROVAL:
                    if auto_approve:
                        result_data = {"approved": True, "auto": True}
                        success = True
                        error = ""
                    else:
                        result_data = {"approved": False, "awaiting": True}
                        success = True
                        error = ""

                elif step.step_type == WorkflowStepType.CONDITIONAL:
                    result_data = self._execute_conditional(state, step, completed)
                    success = True
                    error = ""

                else:
                    result_data = {}
                    success = False
                    error = f"Unknown step type: {step.step_type}"
            except Exception as exc:
                logger.exception("Step %s failed: %s", step.id, exc)
                result_data = {}
                success = False
                error = str(exc)

            elapsed = (time.perf_counter() - step_start) * 1000

            step_result = WorkflowStepResult(
                step_id=step.id,
                success=success,
                data=result_data,
                error=error,
                execution_time_ms=elapsed,
            )
            step_results.append(step_result)

            if success:
                completed.add(step.id)
                state.completed_steps.append(step.id)
                if progress_callback:
                    progress_callback.on_step_complete(step.id, step_name, idx, total_steps, elapsed)
            else:
                logger.error("Workflow step %s failed: %s", step.id, error)
                if progress_callback:
                    progress_callback.on_step_failed(step.id, step_name, idx, total_steps, error)

            state.updated_at = datetime.now(UTC).isoformat()

        total_elapsed = (time.perf_counter() - total_start) * 1000

        if all(r.success for r in step_results):
            state.status = InvestigationStatus.COMPLETED
        else:
            state.status = InvestigationStatus.PAUSED

        return WorkflowResult(
            workflow_name=workflow.name,
            success=all(r.success for r in step_results),
            step_results=step_results,
            total_execution_time_ms=total_elapsed,
        )

    # ── Builtin Step Handlers ────────────────────────────────────────────────

    def _resolve_step_variables(
        self,
        step: WorkflowStepDefinition,
        state: InvestigationSessionState,
    ) -> WorkflowStepDefinition:
        """Resolve {{ variable }} references in step attributes."""
        subs = {
            "target": state.target,
            "technologies": ", ".join(state.scope.technologies) if state.scope.technologies else "unknown",
            "scope": ", ".join(e.value for e in state.scope.entries) if state.scope.entries else state.target,
            "session_id": state.session_id,
            "name": state.name,
            "status": state.status.value,
            "profile": state.checkpoint_data.get("profile_name", ""),
            "framework": state.variables.framework,
            "cloud_provider": state.variables.cloud_provider,
            "auth_method": state.variables.auth_method,
        }

        def resolve(text: str) -> str:
            if not isinstance(text, str):
                return text
            for key, val in subs.items():
                text = text.replace(f"{{{{{key}}}}}", str(val))
                text = text.replace(f"{{{key}}}", str(val))
            return text

        step.id = resolve(step.id)
        step.name = resolve(step.name)
        step.description = resolve(step.description)
        step.action = resolve(step.action)
        step.condition = resolve(step.condition)
        step.approval_message = resolve(step.approval_message)

        if step.prompt_template:
            step.prompt_template = resolve(step.prompt_template)

        if step.config:
            step.config = {k: resolve(str(v)) if isinstance(v, str) else v for k, v in step.config.items()}

        return step

    def _execute_builtin(
        self,
        state: InvestigationSessionState,
        step: WorkflowStepDefinition,
    ) -> dict[str, Any]:
        """Execute a built-in workflow action."""
        step = self._resolve_step_variables(step, state)
        action = step.action
        handler_map: dict[str, Callable] = {
            "load_scope": self._handle_load_scope,
            "import_recon": self._handle_import_recon,
            "normalize_recon": self._handle_normalize_recon,
            "build_attack_surface_graph": self._handle_build_graph,
            "identify_technologies": self._handle_identify_technologies,
            "select_knowledge_packs": self._handle_select_knowledge_packs,
            "select_methodology": self._handle_select_methodology,
            "generate_plan": self._handle_generate_plan,
            "build_context": self._handle_build_context,
            "execute_tasks": self._handle_execute_tasks,
            "collect_evidence": self._handle_collect_evidence,
            "draft_report": self._handle_draft_report,
            "review_findings": self._handle_review_findings,
            "export_report": self._handle_export_report,
            "interactive_review": self._handle_interactive_review,
        }

        handler = handler_map.get(action)
        if handler is None:
            raise InvestigationError(f"Unknown builtin action: {action}")

        return handler(state, step)

    def _handle_load_scope(
        self, state: InvestigationSessionState, step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        """Load scope from step config or existing state."""
        config = step.config or {}
        target = config.get("target", state.target)
        if target and not state.scope.target:
            state.scope.target = target
        for entry_value in config.get("in_scope", []):
            if not any(e.value == entry_value for e in state.scope.entries):
                state.scope.entries.append(
                    ScopeEntry(value=entry_value, entry_type=ScopeEntryType.IN_SCOPE)
                )
        for entry_value in config.get("out_of_scope", []):
            if not any(e.value == entry_value for e in state.scope.entries):
                state.scope.entries.append(
                    ScopeEntry(value=entry_value, entry_type=ScopeEntryType.OUT_OF_SCOPE)
                )
        state.status = InvestigationStatus.SCOPE_LOADED
        return {"target": state.scope.target, "entries": len(state.scope.entries)}

    def _handle_import_recon(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        """Import recon data — creates observations in the reasoning session."""
        reasoning = self.get_reasoning_session(state)
        if not reasoning:
            return {"error": "No reasoning session"}

        for target in [state.scope.target] + [
            e.value for e in state.scope.entries
            if e.entry_type == ScopeEntryType.IN_SCOPE
        ]:
            obs = reasoning.create_observation(
                obs_type="endpoint",
                description=f"In-scope target: {target}",
                source="workflow:import_recon",
                tags=["recon", "scope"],
            )
            reasoning.add_evidence(
                observation_id=obs.id,
                content=f"Target {target} is in scope for investigation",
                source="workflow",
                ev_type="raw",
            )

        state.status = InvestigationStatus.RECON_COMPLETED
        return {"observations_created": len(state.scope.entries)}

    def _handle_normalize_recon(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        entries = state.scope.entries
        original_count = len(entries)

        seen: set[str] = set()
        normalized_entries: list[ScopeEntry] = []
        duplicates = 0

        for entry in entries:
            normalized = entry.value.strip().rstrip("/").lower()
            if not normalized:
                duplicates += 1
                continue
            if normalized in seen:
                duplicates += 1
                continue
            seen.add(normalized)
            normalized_entries.append(entry)

        state.scope.entries = normalized_entries
        return {
            "status": "normalized",
            "original_count": original_count,
            "deduplicated": duplicates,
            "remaining": len(normalized_entries),
        }

    def _handle_build_graph(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        reasoning = self.get_reasoning_session(state)
        graph_nodes = 0
        for entry in state.scope.entries:
            if reasoning:
                reasoning.create_observation(
                    obs_type="endpoint",
                    description=f"Attack surface entry: {entry.value} ({entry.entry_type.value})",
                    source="workflow:build_attack_surface_graph",
                    tags=["attack_surface", entry.entry_type.value],
                )
            graph_nodes += 1

        for tech in state.scope.technologies:
            if reasoning:
                reasoning.create_observation(
                    obs_type="technology",
                    description=f"Technology in attack surface: {tech}",
                    source="workflow:build_attack_surface_graph",
                    tags=["technology", tech.lower()],
                )

        state.status = InvestigationStatus.GRAPH_BUILT
        return {
            "graph_built": True,
            "nodes": graph_nodes,
            "technologies": len(state.scope.technologies),
        }

    def _handle_identify_technologies(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        reasoning = self.get_reasoning_session(state)
        detected: list[str] = list(state.scope.technologies)

        if not detected:
            in_scope_urls = [e.value for e in state.scope.entries if e.entry_type == ScopeEntryType.IN_SCOPE]
            for url in in_scope_urls:
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                detected = self._detect_technologies(url)
                if detected:
                    break

        state.scope.technologies = detected
        if reasoning:
            for tech in detected:
                reasoning.create_observation(
                    obs_type="technology",
                    description=f"Identified technology: {tech}",
                    source="workflow:identify_technologies",
                    tags=["technology", tech.lower()],
                )
        state.status = InvestigationStatus.TECHNOLOGIES_IDENTIFIED
        return {"technologies": state.scope.technologies}

    def _detect_technologies(self, url: str) -> list[str]:
        technologies: set[str] = set()
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "DeepHunter/1.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                self._detect_from_headers(headers, technologies)

                if resp.headers.get_content_type() in ("text/html", "application/xhtml+xml"):
                    try:
                        body = resp.read(65536).decode("utf-8", errors="ignore")
                        self._detect_from_html(body, technologies)
                    except Exception:
                        pass
        except Exception:
            pass

        return sorted(technologies)

    def _detect_from_headers(self, headers: dict[str, str], technologies: set[str]) -> None:
        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()
        via = headers.get("via", "").lower()

        if not server and not powered_by and not via:
            return

        if "apache" in server:
            technologies.add("Apache")
        if "nginx" in server:
            technologies.add("Nginx")
        if "iis" in server or "microsoft-iis" in server:
            technologies.add("IIS")
        if "litespeed" in server:
            technologies.add("LiteSpeed")
        if "nodejs" in server or "node" in server:
            technologies.add("Node.js")

        if "php" in powered_by:
            technologies.add("PHP")
        if "asp.net" in powered_by:
            technologies.add("ASP.NET")
        if "express" in powered_by:
            technologies.add("Express")
        if "django" in powered_by:
            technologies.add("Django")
        if "rails" in powered_by or "ruby" in powered_by:
            technologies.add("Ruby on Rails")
        if "laravel" in powered_by:
            technologies.add("Laravel")
        if "spring" in powered_by:
            technologies.add("Spring")
        if "fastapi" in powered_by:
            technologies.add("FastAPI")
        if "flask" in powered_by:
            technologies.add("Flask")

        if "cloudflare" in via:
            technologies.add("Cloudflare")

    def _detect_from_html(self, html: str, technologies: set[str]) -> None:
        html_lower = html.lower()
        if "wp-content" in html_lower or "wordpress" in html_lower:
            technologies.add("WordPress")
        if "drupal" in html_lower:
            technologies.add("Drupal")
        if "joomla" in html_lower:
            technologies.add("Joomla")
        if "wp-json" in html_lower or 'rel="https://api.w.org"' in html_lower:
            technologies.add("WordPress")
        if "react" in html_lower and ("reactjs" in html_lower or "react.js" in html_lower):
            technologies.add("React")
        if "vue" in html_lower and (".vue" in html_lower or "vuejs" in html_lower):
            technologies.add("Vue.js")
        if "angular" in html_lower:
            technologies.add("Angular")
        if "next.js" in html_lower or '__next' in html_lower:
            technologies.add("Next.js")
        if "nuxt" in html_lower:
            technologies.add("Nuxt.js")
        if "jquery" in html_lower:
            technologies.add("jQuery")
        if "bootstrap" in html_lower:
            technologies.add("Bootstrap")
        if "tailwind" in html_lower:
            technologies.add("Tailwind CSS")
        if "<form" in html_lower and "django" in html_lower:
            technologies.add("Django")
        if "flask" in html_lower:
            technologies.add("Flask")
        if "laravel" in html_lower:
            technologies.add("Laravel")
        if "symfony" in html_lower:
            technologies.add("Symfony")
        if "spring" in html_lower:
            technologies.add("Spring")
        if "wp-admin" in html_lower:
            technologies.add("WordPress")
        if "cdn.tail" in html_lower or "tailwindcss" in html_lower:
            technologies.add("Tailwind CSS")
        if "_nuxt" in html_lower:
            technologies.add("Nuxt.js")
        if "__NEXT_DATA__" in html_lower:
            technologies.add("Next.js")

    def _handle_select_knowledge_packs(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        registry = _get_kp_registry()
        selected: list[str] = []
        for tech in state.scope.technologies:
            packs = registry.get_by_technology(tech)
            for pack in packs:
                if pack.name not in selected:
                    selected.append(pack.name)

        if not selected:
            from deephunter.knowledge.packs.base import KnowledgePackCategory
            universal_categories = [
                KnowledgePackCategory.API,
                KnowledgePackCategory.AUTHENTICATION,
                KnowledgePackCategory.AUTHORIZATION,
                KnowledgePackCategory.BUSINESS_LOGIC,
            ]
            for cat in universal_categories:
                for pack in registry.get_by_category(cat):
                    if pack.name not in selected:
                        selected.append(pack.name)

        state.selected_knowledge_packs = selected
        state.status = InvestigationStatus.KNOWLEDGE_PACKS_SELECTED
        return {"selected_packs": selected}

    def _handle_select_methodology(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        from deephunter.methodology.packs.registry import get_packs_by_technology

        selected: list[str] = []
        cross_cutting: list[str] = []

        for tech in state.scope.technologies:
            packs = get_packs_by_technology(tech)
            for pack in packs:
                if pack.name not in selected:
                    selected.append(pack.name)

        from deephunter.methodology.packs.base import PackCategory
        from deephunter.methodology.packs.registry import _REGISTRY
        if _REGISTRY.count() == 0:
            from deephunter.methodology.packs.registry import load_all_packs
            load_all_packs()

        if not selected:
            for pack in _REGISTRY.get_by_category(PackCategory.CROSS_CUTTING):
                if pack.name not in cross_cutting:
                    cross_cutting.append(pack.name)

        state.selected_methodology_packs = selected or cross_cutting
        state.status = InvestigationStatus.METHODOLOGY_SELECTED
        return {"selected_methodology_packs": state.selected_methodology_packs}

    def _handle_generate_plan(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        planner_cls = _get_planner()
        planner = planner_cls()

        reasoning = self.get_reasoning_session(state)
        if reasoning:
            result = planner.plan_from_session(reasoning)
        else:
            from deephunter.planning import PlannerContext
            ctx = PlannerContext(
                target=state.target,
                technologies=state.scope.technologies,
            )
            result = planner.plan_from_context(ctx)

        state.planner_result_id = f"plan-{id(result)}"

        tasks = self._plan_to_tasks(result, state)
        state.tasks = tasks
        state.status = InvestigationStatus.PLAN_GENERATED
        return {
            "steps": len(result.plan.steps) if hasattr(result, "plan") else 0,
            "tasks_created": len(tasks),
        }

    def _handle_build_context(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        try:
            context_engine_cls = _get_context_engine()
            context_engine = context_engine_cls()
            reasoning = self.get_reasoning_session(state)

            context = context_engine.build(
                investigation_id=state.session_id,
                plan_id=state.planner_result_id or "",
                session=reasoning,
            )
            state.checkpoint_data["context"] = context.model_dump() if context else {}
            state.checkpoint_data["context_built"] = True
            state.status = InvestigationStatus.CONTEXT_BUILT
            return {"context_built": True, "sections": len(context.sections) if context and hasattr(context, 'sections') else 0}
        except Exception as exc:
            logger.warning("Context building failed (non-fatal): %s", exc)
            state.checkpoint_data["context_built"] = True
            state.status = InvestigationStatus.CONTEXT_BUILT
            return {"context_built": True, "warning": str(exc)}

    def _handle_execute_tasks(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        pending = [t for t in state.tasks if t.status == TaskStatus.PENDING]
        if not pending:
            return {"tasks_executed": 0, "message": "No pending tasks"}

        results = self.execute_tasks(state)
        completed = sum(1 for r in results.values() if r == "completed")
        failed = sum(1 for v in results.values() if v.startswith("failed") or v.startswith("error"))
        state.status = InvestigationStatus.IN_PROGRESS
        return {
            "tasks_executed": len(pending),
            "completed": completed,
            "failed": failed,
            "details": results,
        }

    def _handle_collect_evidence(
        self, state: InvestigationSessionState, step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        reasoning = self.get_reasoning_session(state)
        if not reasoning:
            return {"evidence_collected": 0}

        manager = EvidenceManager(state)
        count_before = manager.count()

        for obs in reasoning.state.observations:
            manager.record_evidence(
                title=obs.description[:80],
                content=obs.detail or obs.description,
                evidence_type=EvidenceType.OBSERVATION,
                source_step=step.id,
                tags=obs.tags,
            )
        for ev in reasoning.state.evidence:
            manager.record_evidence(
                title=f"Evidence: {ev.content[:60]}",
                content=ev.content,
                evidence_type=EvidenceType.HTTP_RESPONSE,
                source_step=step.id,
                tags=["reasoning", ev.type.value],
            )

        collected = manager.count() - count_before
        return {"evidence_collected": collected}

    def _handle_draft_report(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        generator = ReportGenerator(state)
        report = generator.generate()
        state.report_id = f"report-{id(report)}"
        return {"report_generated": True, "sections": 12}

    def _handle_review_findings(
        self, state: InvestigationSessionState, _step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        return {"findings_reviewed": len(state.get_tasks_by_status(TaskStatus.COMPLETED))}

    def _handle_export_report(
        self, state: InvestigationSessionState, step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        generator = ReportGenerator(state)
        report = generator.generate()
        markdown = report.to_markdown()
        config = step.config or {}
        export_path = config.get("path", f"report_{state.target.replace('://', '_')}.md")
        Path(export_path).write_text(markdown, "utf-8")
        return {"exported": True, "path": export_path}

    def _handle_interactive_review(
        self, state: InvestigationSessionState, step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        """Display investigation summary and await researcher confirmation."""
        from deephunter.investigation.profiles import get_profile

        profile_name = state.checkpoint_data.get("profile_name", "bugbounty")
        profile = get_profile(profile_name) if profile_name else None

        config = step.config or {}
        auto_approved = config.get("auto_approved", False)

        lines = [
            "\n" + "=" * 60,
            "INVESTIGATION REVIEW",
            "=" * 60,
            "",
            f"Target: {state.target}",
            f"Name: {state.name or 'Unnamed'}",
            f"Session: {state.session_id}",
            f"Status: {state.status.value}",
            "",
        ]

        if state.scope.entries:
            in_scope = state.in_scope
            out_scope = state.out_of_scope
            lines.append(f"Scope: {len(in_scope)} in-scope, {len(out_scope)} out-of-scope")
            for e in in_scope[:5]:
                lines.append(f"  + {e.value}")
            if len(in_scope) > 5:
                lines.append(f"  ... and {len(in_scope) - 5} more")

        if state.scope.technologies:
            lines.append("")
            lines.append(f"Technologies: {', '.join(state.scope.technologies[:10])}")
            if len(state.scope.technologies) > 10:
                lines.append(f"  ... and {len(state.scope.technologies) - 10} more")

        if state.selected_knowledge_packs:
            lines.append(f"Knowledge Packs: {len(state.selected_knowledge_packs)}")

        if state.selected_methodology_packs:
            lines.append(f"Methodology Packs: {len(state.selected_methodology_packs)}")

        if state.tasks:
            pending = state.get_tasks_by_status(TaskStatus.PENDING)
            completed = state.get_tasks_by_status(TaskStatus.COMPLETED)
            failed = state.get_tasks_by_status(TaskStatus.FAILED)
            lines.append("")
            lines.append(f"Tasks: {len(state.tasks)} total")
            lines.append(f"  Pending: {len(pending)}")
            lines.append(f"  Completed: {len(completed)}")
            lines.append(f"  Failed: {len(failed)}")

        if state.evidence:
            lines.append(f"Evidence: {len(state.evidence)} records")

        lines.append("")
        if profile:
            lines.append(f"Estimated Duration: ~{profile.estimated_duration_minutes} minutes")
            lines.append(f"Estimated Cost: ~${profile.estimated_cost_usd:.2f}")
        lines.append("")
        lines.append("=" * 60)
        lines.append("Ready to begin active investigation.")
        if auto_approved:
            lines.append("(Auto-approved - continuing)")
        else:
            lines.append("Press ENTER to continue or Ctrl+C to abort...")
        lines.append("=" * 60 + "\n")

        summary_text = "\n".join(lines)

        if not auto_approved:
            try:
                import click
                click.pause(summary_text + "\n")
            except click.Abort:
                raise InvestigationError("Investigation cancelled by user")

        return {
            "review_displayed": True,
            "summary_lines": len(lines),
            "tasks_pending": len(state.get_tasks_by_status(TaskStatus.PENDING)),
            "user_confirmed": True,
        }

    # ── AI Step Handler ─────────────────────────────────────────────────────

    def _execute_ai_step(
        self, state: InvestigationSessionState, step: WorkflowStepDefinition
    ) -> dict[str, Any]:
        """Execute an AI-assisted workflow step using the ModelRouter."""
        router = _get_model_router()

        from deephunter.router.models import ModelRequest

        max_tokens = min(step.config.get("max_tokens", 4096) if step.config else 4096, 16384)

        request = ModelRequest(
            task_type=step.task_type or "reasoning",
            max_tokens=max_tokens,
        )

        template = step.prompt_template or ""
        substitutions = {
            "target": state.target,
            "technologies": ", ".join(state.scope.technologies) if state.scope.technologies else "unknown",
            "scope": ", ".join(e.value for e in state.scope.entries) if state.scope.entries else state.target,
        }
        for var, val in substitutions.items():
            template = template.replace(f"{{{{{var}}}}}", val)
            template = template.replace(f"{{{var}}}", val)

        prompt = template.strip() or f"Analyze {state.target} for investigation step: {step.name or step.id}"

        max_context_chars = 200_000
        est_tokens = len(prompt) // 3
        if est_tokens > max_tokens * 3:
            excess_ratio = (est_tokens) / (max_tokens * 3)
            if excess_ratio > 2:
                head_size = len(prompt) // 3
                tail_size = len(prompt) // 3
                prompt = (
                    prompt[:head_size] +
                    f"\n\n[...CONTEXT TRUNCATED: {est_tokens - 2 * head_size} characters removed...]\n\n" +
                    prompt[-tail_size:]
                )
                logger.warning(
                    "AI step %s context heavily truncated: ~%d tokens (removed ~%d chars)",
                    step.id,
                    max_tokens * 3 // 3,
                    int(excess_ratio * 100) - 100,
                )
            else:
                prompt = prompt[:max_context_chars]
                logger.warning(
                    "AI step %s prompt truncated: ~%d tokens exceeds limit of ~%d",
                    step.id,
                    est_tokens,
                    max_tokens,
                )

        try:
            response = router.execute(request, prompt=prompt)
            return {
                "ai_response": response.content,
                "model": response.model,
                "provider": response.provider,
            }
        except Exception as exc:
            logger.warning("AI step %s failed (non-fatal): %s", step.id, exc)
            return {
                "ai_response": None,
                "error": str(exc),
                "fallback": True,
            }

    # ── Conditional Step Handler ────────────────────────────────────────────

    def _execute_conditional(
        self,
        state: InvestigationSessionState,
        step: WorkflowStepDefinition,
        completed: set[str],
    ) -> dict[str, Any]:
        """Execute conditional branching based on investigation state."""
        if not step.condition:
            return {"branch": "none", "error": "No condition defined"}

        condition = step.condition
        result = False

        if condition == "has_tasks":
            result = len(state.tasks) > 0
        elif condition == "has_evidence":
            result = len(state.evidence) > 0
        elif condition == "has_findings":
            result = len(state.get_tasks_by_status(TaskStatus.COMPLETED)) > 0
        elif condition == "has_recon":
            result = state.status.value >= InvestigationStatus.RECON_COMPLETED.value
        elif condition == "has_technologies":
            result = len(state.scope.technologies) > 0
        elif condition.startswith("status:"):
            expected = condition.split(":", 1)[1]
            result = state.status.value == expected

        branch_key = "true" if result else "false"
        branch_steps = step.branches.get(branch_key, [])
        for bs in branch_steps:
            completed.add(bs)

        return {
            "condition": condition,
            "result": result,
            "branch": branch_key,
            "steps_scheduled": len(branch_steps),
        }

    # ── Task Engine ─────────────────────────────────────────────────────────

    def create_task(
        self,
        state: InvestigationSessionState,
        title: str,
        description: str = "",
        category: TaskCategory = TaskCategory.OTHER,
        priority: TaskPriority = TaskPriority.MEDIUM,
        dependencies: list[str] | None = None,
    ) -> Task:
        """Create and register a new investigation task."""
        task = Task(
            title=title,
            description=description,
            category=category,
            priority=priority,
            dependencies=dependencies or [],
        )
        state.tasks.append(task)
        return task

    def update_task_status(
        self,
        state: InvestigationSessionState,
        task_id: str,
        status: TaskStatus,
        notes: str = "",
    ) -> Task | None:
        """Update the status of a task."""
        for task in state.tasks:
            if task.id == task_id:
                task.status = status
                task.notes = notes or task.notes
                task.updated_at = datetime.now(UTC).isoformat()
                if status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                    task.completed_at = datetime.now(UTC).isoformat()
                return task
        return None

    def execute_tasks(
        self,
        state: InvestigationSessionState,
        task_ids: list[str] | None = None,
    ) -> dict[str, str]:
        """Execute tasks through the AgentOrchestratorV2.

        Maps task categories to workflow agents and executes them.
        """
        orchestrator = _get_orchestrator_v2()
        reasoning = self.get_reasoning_session(state)
        from deephunter.agents.context import AgentExecutionContext

        tasks_to_run = [
            t for t in state.tasks
            if (task_ids is None or t.id in task_ids)
            and t.status == TaskStatus.PENDING
        ]

        results: dict[str, str] = {}
        for task in tasks_to_run:
            agent_name = self._task_category_to_agent(task.category)
            task.status = TaskStatus.IN_PROGRESS

            try:
                ctx = AgentExecutionContext(shared_data={
                    "target": state.target,
                    "task_id": task.id,
                    "task_title": task.title,
                    "task_description": task.description,
                    "task_category": task.category.value,
                })
                response = orchestrator.execute(agent_name, ctx)
                if response.success:
                    task.status = TaskStatus.COMPLETED
                    results[task.id] = "completed"
                    self._record_agent_findings(getattr(response, 'output_data', None), reasoning, task)
                else:
                    task.status = TaskStatus.FAILED
                    task.notes = response.error or "Agent execution failed"
                    results[task.id] = f"failed: {task.notes}"
            except Exception as exc:
                task.status = TaskStatus.FAILED
                task.notes = str(exc)
                results[task.id] = f"error: {str(exc)}"

            task.updated_at = datetime.now(UTC).isoformat()

        return results

    def _record_agent_findings(
        self,
        output_data: dict[str, Any] | None,
        reasoning: Any,
        task: Task,
    ) -> None:
        """Extract findings from agent output and record as observations."""
        if not reasoning or not output_data:
            return

        content_lines: list[str] = []

        if isinstance(output_data, dict):
            for key, value in output_data.items():
                if key in ("result", "data"):
                    continue
                if isinstance(value, list) and value:
                    content_lines.append(f"{key}: {len(value)} item(s)")
                elif isinstance(value, str) and value:
                    content_lines.append(f"{key}: {value[:200]}")
                elif value:
                    content_lines.append(f"{key}: {str(value)[:200]}")

        if not content_lines:
            return

        summary = f"Task '{task.title}' findings:\n" + "\n".join(content_lines)
        obs = reasoning.create_observation(
            obs_type="finding",
            description=f"Agent finding from {task.category.value} investigation: {task.title}",
            source=f"agent:{task.category.value}",
            tags=["finding", task.category.value, "agent"],
        )
        reasoning.add_evidence(
            observation_id=obs.id,
            content=summary,
            source=f"agent:{task.category.value}",
            ev_type="finding",
        )

    def get_pending_tasks(self, state: InvestigationSessionState) -> list[Task]:
        """Get all pending tasks, sorted by priority."""
        return sorted(
            [t for t in state.tasks if t.status == TaskStatus.PENDING],
            key=lambda t: _priority_sort_key(t.priority),
        )

    # ── Report Generation ──────────────────────────────────────────────────

    def generate_report(
        self,
        state: InvestigationSessionState,
        executive_summary: str = "",
    ) -> InvestigationReport:
        """Generate a structured investigation report."""
        generator = ReportGenerator(state)
        return generator.generate(executive_summary=executive_summary)

    def export_report(
        self,
        state: InvestigationSessionState,
        path: str | Path,
        executive_summary: str = "",
    ) -> str:
        """Generate and export the investigation report as Markdown."""
        report = self.generate_report(state, executive_summary=executive_summary)
        markdown = report.to_markdown()
        p = Path(path)
        p.write_text(markdown, "utf-8")
        return str(p)

    # ── Manual Notes ───────────────────────────────────────────────────────

    def add_note(
        self,
        state: InvestigationSessionState,
        content: str,
        tags: list[str] | None = None,
        source_step: str = "",
    ) -> None:
        """Add a manual researcher note."""
        from deephunter.investigation.models import ManualNote
        state.notes.append(ManualNote(
            content=content,
            tags=tags or [],
            source_step=source_step,
        ))

    # ── Checkpoint / Recovery ──────────────────────────────────────────────

    def checkpoint(
        self,
        state: InvestigationSessionState,
        path: str | Path,
    ) -> str:
        """Save a checkpoint that can be resumed later."""
        saved = self.save_session(state, path)
        state.checkpoint_data["last_checkpoint"] = str(saved)
        state.checkpoint_data["checkpoint_time"] = datetime.now(UTC).isoformat()
        return str(saved)

    def resume(
        self,
        path: str | Path,
        _auto_approve: bool = False,
    ) -> tuple[InvestigationSessionState, WorkflowDefinition | None]:
        """Load a session and return it ready to resume.

        Args:
            path: Path to the saved session JSON.
            auto_approve: Whether to auto-approve pending approvals.

        Returns:
            A tuple of (state, workflow) where workflow is None if not
            associated with a workflow.
        """
        state = self.load_session(path)

        if state.status == InvestigationStatus.PAUSED:
            state.status = InvestigationStatus.IN_PROGRESS

        workflow_name = state.checkpoint_data.get("workflow_name", "")
        workflow: WorkflowDefinition | None = None
        if workflow_name:
            try:
                workflow = self.load_workflow_by_name(workflow_name)
            except FileNotFoundError:
                logger.warning("Workflow %s not found for resume", workflow_name)

        return state, workflow

    # ── Schedule Workflow Step ─────────────────────────────────────────────

    def schedule_step(
        self,
        state: InvestigationSessionState,
        step_id: str,
        step_type: str = "builtin",
        config: dict[str, Any] | None = None,
        depends_on: list[str] | None = None,
    ) -> None:
        """Schedule a workflow step for later execution."""
        state.checkpoint_data.setdefault("scheduled_steps", [])
        state.checkpoint_data["scheduled_steps"].append({
            "id": step_id,
            "type": step_type,
            "config": config or {},
            "depends_on": depends_on or [],
        })

    # ── Internal Helpers ───────────────────────────────────────────────────

    def _plan_to_tasks(
        self,
        plan_result: Any,
        state: InvestigationSessionState,
    ) -> list[Task]:
        """Convert a Planner result into investigation tasks."""
        tasks: list[Task] = []

        if hasattr(plan_result, "plan") and hasattr(plan_result.plan, "steps"):
            for step in plan_result.plan.steps:
                category = self._step_to_category(step)
                tasks.append(Task(
                    title=step.title if hasattr(step, "title") else str(step),
                    description=step.description if hasattr(step, "description") else "",
                    category=category,
                    priority=_step_priority_to_task_priority(step),
                ))

        if not tasks:
            tasks = self._generate_default_tasks(state)

        return tasks

    def _generate_default_tasks(self, state: InvestigationSessionState) -> list[Task]:
        """Generate default investigation tasks when planner yields none."""
        tasks: list[Task] = []
        categories = [
            (TaskCategory.RECON, TaskPriority.HIGH),
            (TaskCategory.AUTHENTICATION, TaskPriority.HIGH),
            (TaskCategory.AUTHORIZATION, TaskPriority.HIGH),
            (TaskCategory.BUSINESS_LOGIC, TaskPriority.MEDIUM),
            (TaskCategory.API, TaskPriority.MEDIUM),
            (TaskCategory.SESSION, TaskPriority.MEDIUM),
            (TaskCategory.FILE_UPLOAD, TaskPriority.MEDIUM),
            (TaskCategory.XSS, TaskPriority.MEDIUM),
            (TaskCategory.SQL_INJECTION, TaskPriority.MEDIUM),
            (TaskCategory.JAVASCRIPT, TaskPriority.LOW),
        ]
        for cat, pri in categories:
            cat_title = cat.value.replace("_", " ").title()
            tasks.append(Task(
                title=f"Review {cat_title}",
                description=f"Investigate {cat_title.lower()} attack surface for {state.target}",
                category=cat,
                priority=pri,
            ))
        return tasks

    @staticmethod
    def _step_to_category(step: Any) -> TaskCategory:
        title = ""
        if hasattr(step, "title"):
            title = step.title or ""
        if hasattr(step, "phase") and hasattr(step.phase, "value"):
            title = f"{step.phase.value} {title}"

        title_lower = title.lower()
        for cat in TaskCategory:
            if cat.value in title_lower:
                return cat
        return TaskCategory.OTHER

    @staticmethod
    def _task_category_to_agent(category: TaskCategory) -> str:
        mapping: dict[TaskCategory, str] = {
            TaskCategory.AUTHENTICATION: "auth_review",
            TaskCategory.AUTHORIZATION: "authorization_review",
            TaskCategory.BUSINESS_LOGIC: "business_logic",
            TaskCategory.JAVASCRIPT: "javascript_review",
            TaskCategory.API: "api_review",
            TaskCategory.CLOUD: "cloud_review",
            TaskCategory.RECON: "initial_recon",
            TaskCategory.SESSION: "auth_review",
            TaskCategory.GRAPHQL: "api_review",
            TaskCategory.SQL_INJECTION: "api_review",
            TaskCategory.XSS: "api_review",
            TaskCategory.SSRF: "api_review",
            TaskCategory.RCE: "api_review",
            TaskCategory.LFI: "api_review",
            TaskCategory.IDOR: "api_review",
            TaskCategory.FILE_UPLOAD: "api_review",
            TaskCategory.RATE_LIMIT: "api_review",
            TaskCategory.OTHER: "initial_recon",
        }
        return mapping.get(category, "initial_recon")


def _priority_sort_key(priority: TaskPriority) -> int:
    order = {
        TaskPriority.CRITICAL: 0,
        TaskPriority.HIGH: 1,
        TaskPriority.MEDIUM: 2,
        TaskPriority.LOW: 3,
    }
    return order.get(priority, 99)


def _step_priority_to_task_priority(step: Any) -> TaskPriority:
    if hasattr(step, "priority_score"):
        score = step.priority_score
        if score >= 0.8:
            return TaskPriority.CRITICAL
        elif score >= 0.6:
            return TaskPriority.HIGH
        elif score >= 0.4:
            return TaskPriority.MEDIUM
    return TaskPriority.MEDIUM
