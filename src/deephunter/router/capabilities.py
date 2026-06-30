"""Model capabilities and task-to-capability mapping.

Every provider advertises capabilities.  The router matches tasks to
capabilities, never to provider names.
"""

from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    """Atomic capability that a model may support."""

    REASONING = "reasoning"
    CODE_GENERATION = "code_generation"
    CODE_REVIEW = "code_review"
    LARGE_CONTEXT = "large_context"
    VISION = "vision"
    TOOL_USE = "tool_use"
    JSON_OUTPUT = "json_output"
    STREAMING = "streaming"
    LONG_RUNNING = "long_running"
    FAST_RESPONSE = "fast_response"
    OFFLINE = "offline"
    COST_EFFICIENT = "cost_efficient"
    SAFETY = "safety"
    STRUCTURED_OUTPUT = "structured_output"


class TaskType(str, Enum):
    """Types of tasks the router can handle."""

    REASONING = "reasoning"
    PLANNING = "planning"
    CODE_ANALYSIS = "code_analysis"
    CODE_GENERATION = "code_generation"
    DOCUMENTATION = "documentation"
    REPORT_WRITING = "report_writing"
    SECURITY_ANALYSIS = "security_analysis"
    THREAT_MODELING = "threat_modeling"
    KNOWLEDGE_EXTRACTION = "knowledge_extraction"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    CLASSIFICATION = "classification"
    CONTEXT_COMPRESSION = "context_compression"


TASK_CAPABILITY_MAP: dict[TaskType, set[Capability]] = {
    TaskType.REASONING: {Capability.REASONING, Capability.LARGE_CONTEXT},
    TaskType.PLANNING: {Capability.REASONING, Capability.STRUCTURED_OUTPUT},
    TaskType.CODE_ANALYSIS: {Capability.CODE_REVIEW, Capability.REASONING},
    TaskType.CODE_GENERATION: {Capability.CODE_GENERATION},
    TaskType.DOCUMENTATION: {Capability.CODE_REVIEW},
    TaskType.REPORT_WRITING: {Capability.STRUCTURED_OUTPUT, Capability.LARGE_CONTEXT},
    TaskType.SECURITY_ANALYSIS: {Capability.REASONING, Capability.CODE_REVIEW},
    TaskType.THREAT_MODELING: {Capability.REASONING, Capability.STRUCTURED_OUTPUT},
    TaskType.KNOWLEDGE_EXTRACTION: {Capability.LARGE_CONTEXT},
    TaskType.SUMMARIZATION: {Capability.LARGE_CONTEXT},
    TaskType.TRANSLATION: set(),
    TaskType.CLASSIFICATION: {Capability.STRUCTURED_OUTPUT},
    TaskType.CONTEXT_COMPRESSION: {Capability.LARGE_CONTEXT},
}


def get_capabilities_for_task(task_type: TaskType) -> set[Capability]:
    """Return the set of capabilities required for a given task type."""
    return TASK_CAPABILITY_MAP.get(task_type, set())


def get_capabilities_for_task_str(task_type_str: str) -> set[str]:
    """Return capability strings for a task type string.

    Falls back to empty set if the task type is unknown.
    """
    try:
        task = TaskType(task_type_str)
    except ValueError:
        return set()
    return {c.value for c in TASK_CAPABILITY_MAP.get(task, set())}
