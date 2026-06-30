"""Tests for the workflow DSL loader and step handler."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from deephunter.investigation.workflow import WorkflowLoader, WorkflowStepHandler


class TestWorkflowLoader:
    def test_load_valid_yaml(self) -> None:
        yaml_content = """
name: Test Workflow
description: A test workflow
version: "1.0"
steps:
  - id: step1
    name: Step One
    type: builtin
    action: load_scope
  - id: step2
    name: Step Two
    type: builtin
    action: import_recon
    depends_on:
      - step1
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            loader = WorkflowLoader()
            wf = loader.load(tmp_path)
            assert wf.name == "Test Workflow"
            assert wf.description == "A test workflow"
            assert wf.version == "1.0"
            assert len(wf.steps) == 2
            assert wf.steps[0].id == "step1"
            assert wf.steps[1].id == "step2"
            assert wf.steps[1].depends_on == ["step1"]
        finally:
            os.unlink(tmp_path)

    def test_load_missing_file(self) -> None:
        loader = WorkflowLoader()
        with pytest.raises(FileNotFoundError):
            loader.load("/nonexistent/workflow.yaml")

    def test_load_invalid_yaml(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: broken: [")
            tmp_path = f.name

        try:
            loader = WorkflowLoader()
            with pytest.raises(ValueError, match="Invalid YAML"):
                loader.load(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_load_missing_name(self) -> None:
        yaml_content = """
steps:
  - id: step1
    action: load_scope
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            loader = WorkflowLoader()
            with pytest.raises(ValueError, match="must have a 'name' field"):
                loader.load(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_load_no_steps(self) -> None:
        yaml_content = """
name: Empty
steps: []
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            loader = WorkflowLoader()
            with pytest.raises(ValueError, match="at least one step"):
                loader.load(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_load_invalid_step_type(self) -> None:
        yaml_content = """
name: Bad
steps:
  - id: step1
    type: invalid_type
    action: load_scope
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            loader = WorkflowLoader()
            with pytest.raises(ValueError, match="unknown type"):
                loader.load(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_load_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_path = Path(tmpdir) / "test_wf.yaml"
            wf_path.write_text("""
name: Test
steps:
  - id: step1
    type: builtin
    action: load_scope
""")
            loader = WorkflowLoader(workflow_dir=tmpdir)
            wf = loader.load_by_name("test_wf")
            assert wf.name == "Test"

    def test_list_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "wf1.yaml").write_text("name: WF1\ndescription: First workflow\nsteps:\n  - id: s1\n    type: builtin\n    action: load_scope")
            (Path(tmpdir) / "wf2.yaml").write_text("name: WF2\ndescription: Second workflow\nsteps:\n  - id: s1\n    type: builtin\n    action: load_scope")
            loader = WorkflowLoader(workflow_dir=tmpdir)
            workflows = loader.list_workflows()
            assert len(workflows) == 2
            names = {w["name"] for w in workflows}
            assert "wf1" in names
            assert "wf2" in names

    def test_empty_workflow_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = WorkflowLoader(workflow_dir=tmpdir)
            assert loader.list_workflows() == []

    def test_all_step_types(self) -> None:
        yaml_content = """
name: All Types
steps:
  - id: builtin_step
    type: builtin
    action: load_scope
  - id: ai_step
    type: ai
    task_type: reasoning
    prompt_template: "Analyze {target}"
  - id: approval_step
    type: approval
    approval_message: "Proceed?"
  - id: conditional_step
    type: conditional
    condition: "has_tasks"
    branches:
      "true": [step_a]
      "false": [step_b]
  - id: sub_wf_step
    type: sub_workflow
    sub_workflow: nested_workflow
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            loader = WorkflowLoader()
            wf = loader.load(tmp_path)
            assert len(wf.steps) == 5
            assert wf.steps[0].step_type.value == "builtin"
            assert wf.steps[1].step_type.value == "ai"
            assert wf.steps[2].step_type.value == "approval"
            assert wf.steps[3].step_type.value == "conditional"
            assert wf.steps[4].step_type.value == "sub_workflow"
        finally:
            os.unlink(tmp_path)


class TestWorkflowStepHandler:
    def test_valid_builtin_actions(self) -> None:
        assert WorkflowStepHandler.is_valid_builtin_action("load_scope")
        assert WorkflowStepHandler.is_valid_builtin_action("import_recon")
        assert WorkflowStepHandler.is_valid_builtin_action("draft_report")
        assert WorkflowStepHandler.is_valid_builtin_action("export_report")
        assert not WorkflowStepHandler.is_valid_builtin_action("nonexistent")

    def test_valid_ai_task_types(self) -> None:
        assert WorkflowStepHandler.is_valid_ai_task_type("reasoning")
        assert WorkflowStepHandler.is_valid_ai_task_type("planning")
        assert not WorkflowStepHandler.is_valid_ai_task_type("nonexistent")

    def test_list_builtin_actions(self) -> None:
        actions = WorkflowStepHandler.list_builtin_actions()
        assert len(actions) >= 13
        assert "load_scope" in actions
        assert "draft_report" in actions

    def test_list_ai_task_types(self) -> None:
        types = WorkflowStepHandler.list_ai_task_types()
        assert len(types) >= 5
        assert "reasoning" in types

    def test_get_action_description(self) -> None:
        desc = WorkflowStepHandler.get_builtin_action_description("load_scope")
        assert len(desc) > 0
        assert "scope" in desc.lower()
