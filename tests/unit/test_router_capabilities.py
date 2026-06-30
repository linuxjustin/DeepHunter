"""Tests for router capabilities."""

from __future__ import annotations

from deephunter.router.capabilities import (
    Capability,
    TaskType,
    get_capabilities_for_task,
    get_capabilities_for_task_str,
    TASK_CAPABILITY_MAP,
)


class TestCapability:
    def test_values_present(self) -> None:
        assert Capability.REASONING.value == "reasoning"
        assert Capability.CODE_GENERATION.value == "code_generation"
        assert Capability.VISION.value == "vision"
        assert Capability.OFFLINE.value == "offline"
        assert Capability.COST_EFFICIENT.value == "cost_efficient"

    def test_all_capabilities_defined(self) -> None:
        names = {c.value for c in Capability}
        assert "reasoning" in names
        assert "vision" in names
        assert "streaming" in names
        assert len(names) >= 14


class TestTaskType:
    def test_values_present(self) -> None:
        assert TaskType.REASONING.value == "reasoning"
        assert TaskType.CODE_ANALYSIS.value == "code_analysis"
        assert TaskType.REPORT_WRITING.value == "report_writing"

    def test_all_tasks_defined(self) -> None:
        names = {t.value for t in TaskType}
        assert "reasoning" in names
        assert "planning" in names
        assert "security_analysis" in names
        assert len(names) >= 13


class TestTaskCapabilityMap:
    def test_reasoning_requires_reasoning_and_large_context(self) -> None:
        caps = TASK_CAPABILITY_MAP[TaskType.REASONING]
        assert Capability.REASONING in caps
        assert Capability.LARGE_CONTEXT in caps

    def test_code_analysis_requires_code_review_and_reasoning(self) -> None:
        caps = TASK_CAPABILITY_MAP[TaskType.CODE_ANALYSIS]
        assert Capability.CODE_REVIEW in caps
        assert Capability.REASONING in caps

    def test_report_writing_requires_structured_output(self) -> None:
        caps = TASK_CAPABILITY_MAP[TaskType.REPORT_WRITING]
        assert Capability.STRUCTURED_OUTPUT in caps

    def test_translation_has_no_requirements(self) -> None:
        caps = TASK_CAPABILITY_MAP[TaskType.TRANSLATION]
        assert caps == set()


class TestGetCapabilitiesForTask:
    def test_known_task(self) -> None:
        caps = get_capabilities_for_task(TaskType.REASONING)
        assert Capability.REASONING in caps

    def test_unknown_task(self) -> None:
        # Test via the str version
        caps = get_capabilities_for_task_str("nonexistent_task")
        assert caps == set()

    def test_task_str_reasoning(self) -> None:
        caps = get_capabilities_for_task_str("reasoning")
        assert "reasoning" in caps
        assert "large_context" in caps

    def test_task_str_unknown(self) -> None:
        caps = get_capabilities_for_task_str("")
        assert caps == set()
