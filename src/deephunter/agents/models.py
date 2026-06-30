"""Pydantic models for the Agent Orchestration Framework v2."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class ExecutionStrategyType(str, Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"
    PIPELINE = "pipeline"
    FAN_OUT = "fan_out"
    FAN_IN = "fan_in"


class AgentCapability(BaseModel):
    name: str
    description: str = ""
    required_capabilities: list[str] = Field(default_factory=list)
    supported_tasks: list[str] = Field(default_factory=list)


class AgentDependency(BaseModel):
    agent_name: str
    required: bool = True
    description: str = ""
    timeout_seconds: float | None = None


class AgentMessage(BaseModel):
    id: str = Field(default_factory=lambda: f"msg-{uuid4().hex[:12]}")
    agent_name: str
    message_type: str = "info"
    content: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")
    agent_name: str
    task_type: str = ""
    input_data: dict[str, Any] = Field(default_factory=dict)
    context_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float = 300.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentResponse(BaseModel):
    id: str = Field(default_factory=lambda: f"res-{uuid4().hex[:12]}")
    request_id: str = ""
    agent_name: str
    success: bool = True
    output_data: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    execution_time_ms: float = 0.0
    retry_attempt: int = 0
    messages: list[AgentMessage] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentExecutionPlan(BaseModel):
    id: str = Field(default_factory=lambda: f"plan-{uuid4().hex[:12]}")
    strategy: ExecutionStrategyType = ExecutionStrategyType.SEQUENTIAL
    agent_names: list[str] = Field(default_factory=list)
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    context_id: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
