"""Integration tests for the end-to-end investigation workflow.

Validates that the InvestigationOrchestrator correctly composes
existing DeepHunter subsystems: InvestigationSession, Planner,
AgentOrchestratorV2, ContextEngine, ModelRouter, EvidenceManager,
and ReportGenerator.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from deephunter.investigation.models import (
    InvestigationStatus,
    ScopeEntry,
    ScopeEntryType,
    TaskCategory,
    TaskPriority,
    TaskStatus,
    WorkflowDefinition,
    WorkflowStepDefinition,
    WorkflowStepType,
)
from deephunter.investigation.orchestrator import InvestigationOrchestrator

# ── Helpers ──────────────────────────────────────────────────────────────────


def make_workflow(steps: list[dict]) -> WorkflowDefinition:
    return WorkflowDefinition(
        name="test_workflow",
        description="Test workflow",
        steps=[WorkflowStepDefinition(**s) for s in steps],
    )


def make_simple_workflow() -> WorkflowDefinition:
    return make_workflow([
        {"id": "load_scope", "type": "builtin", "action": "load_scope", "config": {"in_scope": ["https://example.com"]}},
        {"id": "import_recon", "type": "builtin", "action": "import_recon", "depends_on": ["load_scope"]},
        {"id": "identify_technologies", "type": "builtin", "action": "identify_technologies", "depends_on": ["import_recon"]},
        {"id": "select_knowledge_packs", "type": "builtin", "action": "select_knowledge_packs", "depends_on": ["identify_technologies"]},
        {"id": "select_methodology", "type": "builtin", "action": "select_methodology", "depends_on": ["identify_technologies"]},
        {"id": "generate_plan", "type": "builtin", "action": "generate_plan", "depends_on": ["select_knowledge_packs", "select_methodology"]},
        {"id": "collect_evidence", "type": "builtin", "action": "collect_evidence", "depends_on": ["generate_plan"]},
        {"id": "draft_report", "type": "builtin", "action": "draft_report", "depends_on": ["collect_evidence"]},
        {"id": "export_report", "type": "builtin", "action": "export_report", "depends_on": ["draft_report"], "config": {"path": "/tmp/test_report_out.md"}},
    ])


# ── Tests ────────────────────────────────────────────────────────────────────


class TestOrchestratorSessionLifecycle:
    def test_create_session(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        assert state.target == "https://example.com"
        assert state.status == InvestigationStatus.CREATED
        assert state.session_id.startswith("inv-")
        assert state.reasoning_session_id
        assert orch.get_reasoning_session(state) is not None

    def test_create_session_with_technologies(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session(
            "https://example.com",
            name="My Investigation",
            scope_entries=[
                ScopeEntry(value="https://example.com", entry_type=ScopeEntryType.IN_SCOPE),
                ScopeEntry(value="https://api.example.com", entry_type=ScopeEntryType.IN_SCOPE),
            ],
            technologies=["node.js", "express", "mongodb"],
        )
        assert state.name == "My Investigation"
        assert len(state.in_scope) == 2
        assert "node.js" in state.scope.technologies

    def test_save_and_load_session(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com", name="Save Test")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            save_path = f.name

        try:
            orch.save_session(state, save_path)
            assert Path(save_path).exists()

            loaded = orch.load_session(save_path)
            assert loaded.target == "https://example.com"
            assert loaded.name == "Save Test"
            assert loaded.session_id == state.session_id
        finally:
            os.unlink(save_path)
            reasoning_path = Path(save_path).parent / f"{Path(save_path).stem}_reasoning{Path(save_path).suffix}"
            if reasoning_path.exists():
                os.unlink(str(reasoning_path))

    def test_add_note(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        orch.add_note(state, "Interesting behavior in login flow", tags=["login", "observation"], source_step="recon")
        assert len(state.notes) == 1
        assert state.notes[0].content == "Interesting behavior in login flow"
        assert "login" in state.notes[0].tags


class TestOrchestratorWorkflowExecution:
    def test_full_workflow_success(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session(
            "https://example.com",
            technologies=["node.js", "express", "mongodb"],
        )
        workflow = make_simple_workflow()
        result = orch.execute_workflow(state, workflow, auto_approve=True)

        assert result.success, f"Workflow failed: {[r.error for r in result.step_results if not r.success]}"
        assert len(result.step_results) == 9
        assert state.status == InvestigationStatus.COMPLETED
        assert len(state.completed_steps) == 9

    def test_workflow_with_approval_step(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        workflow = make_workflow([
            {"id": "load_scope", "type": "builtin", "action": "load_scope"},
            {"id": "approval_needed", "type": "approval", "approval_message": "Proceed?", "depends_on": ["load_scope"]},
        ])

        # Without auto-approve, the approval step should be pending
        result = orch.execute_workflow(state, workflow, auto_approve=False)
        approval_result = [r for r in result.step_results if r.step_id == "approval_needed"][0]
        assert approval_result.success
        assert approval_result.data.get("approved") is False
        assert approval_result.data.get("awaiting") is True

        # With auto-approve, it should pass
        state2 = orch.create_session("https://example.com")
        result2 = orch.execute_workflow(state2, workflow, auto_approve=True)
        approval_result2 = [r for r in result2.step_results if r.step_id == "approval_needed"][0]
        assert approval_result2.data.get("approved") is True
        assert approval_result2.data.get("auto") is True

    def test_workflow_dependency_gate(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        workflow = make_workflow([
            {"id": "step_a", "type": "builtin", "action": "load_scope"},
            {"id": "step_b", "type": "builtin", "action": "load_scope", "depends_on": ["step_c"]},
        ])
        result = orch.execute_workflow(state, workflow)
        step_b_result = [r for r in result.step_results if r.step_id == "step_b"][0]
        assert not step_b_result.success
        assert "Dependencies not satisfied" in step_b_result.error

    def test_workflow_checkpoint_skip(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        state.completed_steps = ["load_scope", "import_recon"]

        workflow = make_workflow([
            {"id": "load_scope", "type": "builtin", "action": "load_scope"},
            {"id": "import_recon", "type": "builtin", "action": "import_recon", "depends_on": ["load_scope"]},
            {"id": "identify_technologies", "type": "builtin", "action": "identify_technologies", "depends_on": ["import_recon"]},
        ])
        result = orch.execute_workflow(state, workflow)
        assert result.success
        skipped = [r for r in result.step_results if r.data.get("skipped")]
        assert len(skipped) == 2
        executed = [r for r in result.step_results if not r.data.get("skipped")]
        assert len(executed) == 1

    def test_conditional_branch_true(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        workflow = make_workflow([
            {"id": "load_scope", "type": "builtin", "action": "load_scope"},
            {"id": "check", "type": "conditional", "condition": "has_tasks", "branches": {"true": ["task_branch"], "false": ["noop_branch"]}, "depends_on": ["load_scope"]},
        ])
        # Create a task so condition is true
        orch.create_task(state, "Test task")
        result = orch.execute_workflow(state, workflow)
        check_result = [r for r in result.step_results if r.step_id == "check"][0]
        assert check_result.data.get("result") is True
        assert check_result.data.get("branch") == "true"

    def test_conditional_branch_false(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        workflow = make_workflow([
            {"id": "load_scope", "type": "builtin", "action": "load_scope"},
            {"id": "check", "type": "conditional", "condition": "has_findings", "branches": {"true": ["task_branch"], "false": ["noop_branch"]}, "depends_on": ["load_scope"]},
        ])
        result = orch.execute_workflow(state, workflow)
        check_result = [r for r in result.step_results if r.step_id == "check"][0]
        assert check_result.data.get("result") is False
        assert check_result.data.get("branch") == "false"

    def test_workflow_with_callbacks(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")

        def custom_handler(_state, _step):
            return {"custom": "handled"}

        workflow = make_workflow([
            {"id": "custom_step", "type": "builtin", "action": "load_scope"},
        ])
        result = orch.execute_workflow(state, workflow, callbacks={"custom_step": custom_handler})
        assert result.success
        step_result = result.step_results[0]
        assert step_result.data.get("custom") == "handled"


class TestOrchestratorTaskManagement:
    def test_create_task(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        task = orch.create_task(
            state,
            "Review Authentication",
            description="Check for auth bypass",
            category=TaskCategory.AUTHENTICATION,
            priority=TaskPriority.HIGH,
        )
        assert task.id.startswith("task-")
        assert task.title == "Review Authentication"
        assert task.category == TaskCategory.AUTHENTICATION
        assert task.priority == TaskPriority.HIGH
        assert len(state.tasks) == 1

    def test_update_task_status(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        task = orch.create_task(state, "Test task")
        assert orch.update_task_status(state, task.id, TaskStatus.IN_PROGRESS)
        assert state.tasks[0].status == TaskStatus.IN_PROGRESS

        assert orch.update_task_status(state, task.id, TaskStatus.COMPLETED)
        assert state.tasks[0].status == TaskStatus.COMPLETED
        assert state.tasks[0].completed_at is not None

    def test_update_task_status_not_found(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        assert orch.update_task_status(state, "nonexistent", TaskStatus.COMPLETED) is None

    def test_get_pending_tasks_sorted(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        orch.create_task(state, "Low", priority=TaskPriority.LOW)
        orch.create_task(state, "High", priority=TaskPriority.HIGH)
        orch.create_task(state, "Critical", priority=TaskPriority.CRITICAL)

        pending = orch.get_pending_tasks(state)
        assert len(pending) == 3
        assert pending[0].priority == TaskPriority.CRITICAL
        assert pending[1].priority == TaskPriority.HIGH
        assert pending[2].priority == TaskPriority.LOW

    def test_execute_tasks_empty(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        results = orch.execute_tasks(state)
        assert results == {}

    def test_execute_tasks_with_categories(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        # All will try to execute via AgentOrchestratorV2 which won't have
        # the agents registered, so they should fail gracefully
        orch.create_task(state, "Auth", category=TaskCategory.AUTHENTICATION)
        orch.create_task(state, "API", category=TaskCategory.API)
        results = orch.execute_tasks(state, [state.tasks[0].id])
        # Should not crash — agents won't be found but should error gracefully
        assert len(results) == 1


class TestOrchestratorCheckpointing:
    def test_checkpoint_and_resume(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        state.status = InvestigationStatus.PAUSED

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            checkpoint_path = f.name

        try:
            saved = orch.checkpoint(state, checkpoint_path)
            assert Path(saved).exists()

            loaded_state, workflow = orch.resume(checkpoint_path)
            assert loaded_state.session_id == state.session_id
            assert loaded_state.status == InvestigationStatus.IN_PROGRESS
        finally:
            os.unlink(checkpoint_path)
            reasoning_path = Path(checkpoint_path).parent / f"{Path(checkpoint_path).stem}_reasoning{Path(checkpoint_path).suffix}"
            if reasoning_path.exists():
                os.unlink(str(reasoning_path))

    def test_schedule_step(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        orch.schedule_step(state, "future_step", config={"param": "value"}, depends_on=["step1"])
        scheduled = state.checkpoint_data.get("scheduled_steps", [])
        assert len(scheduled) == 1
        assert scheduled[0]["id"] == "future_step"


class TestOrchestratorBuiltins:
    def test_load_scope_with_config(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="load_scope", config={
            "in_scope": ["https://app.example.com", "https://api.example.com"],
            "out_of_scope": ["https://admin.example.com"],
        })
        result = orch._execute_builtin(state, step)
        assert result["target"] == "https://example.com"
        assert result["entries"] == 4  # 1 default + 2 in_scope + 1 out_of_scope

    def test_import_recon(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="import_recon")
        result = orch._execute_builtin(state, step)
        assert result["observations_created"] >= 1

    def test_identify_technologies(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com", technologies=["node.js", "express"])
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="identify_technologies")
        result = orch._execute_builtin(state, step)
        assert result["technologies"] == ["node.js", "express"]

        # Verify observations were created in the reasoning session
        reasoning = orch.get_reasoning_session(state)
        assert reasoning is not None
        tech_obs = [o for o in reasoning.state.observations if o.type.value == "technology"]
        assert len(tech_obs) == 2

    def test_select_knowledge_packs(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com", technologies=["node.js", "express"])
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="select_knowledge_packs")
        result = orch._execute_builtin(state, step)
        assert len(result["selected_packs"]) >= 1
        assert len(state.selected_knowledge_packs) >= 1

    def test_select_methodology(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="select_methodology")
        result = orch._execute_builtin(state, step)
        assert len(result["selected_methodology_packs"]) >= 1

    def test_generate_plan(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="generate_plan")
        result = orch._execute_builtin(state, step)
        assert result["tasks_created"] >= 1
        assert len(state.tasks) >= 1

    def test_collect_evidence(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="collect_evidence")
        # First import some recon to create observations
        orch._execute_builtin(state, WorkflowStepDefinition(id="s1", action="import_recon"))
        result = orch._execute_builtin(state, step)
        assert result["evidence_collected"] >= 0

    def test_draft_report(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition
        step = WorkflowStepDefinition(id="test", action="draft_report")
        result = orch._execute_builtin(state, step)
        assert result["report_generated"]
        assert state.report_id

    def test_export_report(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition
        export_path = "/tmp/test_export_report.md"
        step = WorkflowStepDefinition(id="test", action="export_report", config={"path": export_path})
        try:
            result = orch._execute_builtin(state, step)
            assert result["exported"]
            assert Path(export_path).exists()
        finally:
            if Path(export_path).exists():
                os.unlink(export_path)

    def test_generate_and_export_report(self) -> None:
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com", name="Integration Test")
        xss_task = orch.create_task(state, "XSS Check", category=TaskCategory.XSS)
        xss_task.status = TaskStatus.COMPLETED
        orch.create_task(state, "SQLi Check", category=TaskCategory.SQL_INJECTION, priority=TaskPriority.HIGH)

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            report_path = f.name

        try:
            path = orch.export_report(state, report_path, executive_summary="Custom summary")
            assert Path(path).exists()
            content = Path(path).read_text("utf-8")
            assert "Integration Test" in content
            assert "Custom summary" in content
            assert "XSS Check" in content
        finally:
            os.unlink(report_path)


class TestEndToEndWorkflow:
    """End-to-end workflow that mirrors a real investigation flow."""

    def test_web_app_review_workflow(self) -> None:
        """Execute a complete web application review workflow."""
        orch = InvestigationOrchestrator()
        state = orch.create_session(
            "https://example.com",
            name="E2E Web Review",
            technologies=["node.js", "express", "react", "mongodb"],
        )

        workflow = make_simple_workflow()
        result = orch.execute_workflow(state, workflow, auto_approve=True)
        assert result.success, f"Workflow failed: {[r for r in result.step_results if not r.success]}"

        assert len(state.completed_steps) == 9
        assert state.status == InvestigationStatus.COMPLETED
        assert len(state.tasks) >= 1
        assert state.report_id

        # Verify report generation
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            report_path = f.name
        try:
            path = orch.export_report(state, report_path)
            content = Path(path).read_text("utf-8")
            assert "E2E Web Review" in content
            assert "Executive Summary" in content
            assert "Scope" in content
            assert "node.js" in content
        finally:
            os.unlink(report_path)

    def test_yaml_workflow_loading_and_execution(self) -> None:
        """Test loading a YAML workflow from the workflows/ directory and executing it."""
        # Point the workflow loader to the project's workflows directory
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com", technologies=["node.js", "express"])

        wf_path = Path(__file__).parent.parent.parent / "workflows" / "web_app_review.yaml"
        if not wf_path.exists():
            # Fallback to alternative location
            wf_path = Path("workflows/web_app_review.yaml")

        if wf_path.exists():
            workflow = orch.load_workflow(str(wf_path))
            assert workflow.name == "Web Application Security Review"
            assert len(workflow.steps) >= 15

            result = orch.execute_workflow(state, workflow, auto_approve=True)
            assert result.success, f"YAML workflow failed: {[r.error for r in result.step_results if not r.success]}"
            assert len(state.completed_steps) > 0

    def test_recovery_after_interruption(self) -> None:
        """Test checkpointing and recovery after interruption."""
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com", name="Recovery Test")

        # Simulate completing some steps then interrupting
        state.completed_steps = ["load_scope", "import_recon", "build_graph"]
        state.status = InvestigationStatus.PAUSED

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            ckpt_path = f.name

        try:
            orch.checkpoint(state, ckpt_path)

            # Simulate crash — load from checkpoint
            restored_state, _ = orch.resume(ckpt_path)
            assert restored_state.completed_steps == ["load_scope", "import_recon", "build_graph"]
            assert restored_state.status == InvestigationStatus.IN_PROGRESS
        finally:
            os.unlink(ckpt_path)
            reasoning_path = Path(ckpt_path).parent / f"{Path(ckpt_path).stem}_reasoning{Path(ckpt_path).suffix}"
            if reasoning_path.exists():
                os.unlink(str(reasoning_path))

    def test_ai_step_fallback(self) -> None:
        """Test that AI steps fall back gracefully when no providers are configured."""
        orch = InvestigationOrchestrator()
        state = orch.create_session("https://example.com")
        from deephunter.investigation.models import WorkflowStepDefinition

        step = WorkflowStepDefinition(
            id="ai_test",
            step_type=WorkflowStepType.AI,
            task_type="reasoning",
            prompt_template="Analyze {target}",
        )
        result = orch._execute_ai_step(state, step)
        # Should not crash — should return fallback data
        assert result["ai_response"] is None
        assert result["fallback"] is True
