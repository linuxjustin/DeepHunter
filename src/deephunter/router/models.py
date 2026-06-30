"""Pydantic models for the Model Router & Provider Abstraction Layer."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class ProviderStatus(str, Enum):
    """Operational status of a provider."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ModelInfo(BaseModel):
    """Information about a specific model offered by a provider."""

    id: str = ""
    name: str = ""
    provider_name: str = ""
    capabilities: set[str] = Field(default_factory=set)
    max_tokens: int = 0
    max_context: int = 0
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    supports_streaming: bool = False
    supports_vision: bool = False
    supports_json: bool = False
    supports_tool_use: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderMetadata(BaseModel):
    """Metadata describing an AI provider."""

    name: str = ""
    description: str = ""
    version: str = ""
    website: str = ""
    models: list[ModelInfo] = Field(default_factory=list)
    default_model: str = ""
    api_type: str = ""
    requires_api_key: bool = True
    requires_base_url: bool = False
    environment: str = ""


class ExecutionContext(BaseModel):
    """Context for a routing decision — what the caller needs."""

    task_type: str = "reasoning"
    required_capabilities: set[str] = Field(default_factory=set)
    preferred_capabilities: set[str] = Field(default_factory=set)
    max_tokens: int = 0
    max_cost: float = 0.0
    require_offline: bool = False
    require_streaming: bool = False
    require_vision: bool = False
    require_json: bool = False
    require_tool_use: bool = False
    timeout_seconds: float = 120.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelRequest(BaseModel):
    """A request to the ModelRouter to select a provider+model."""

    id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")
    context_id: str = ""
    prompt_id: str = ""
    task_type: str = "reasoning"
    required_capabilities: set[str] = Field(default_factory=set)
    preferred_capabilities: set[str] = Field(default_factory=set)
    max_tokens: int = 4096
    max_cost: float = 0.0
    require_offline: bool = False
    require_streaming: bool = False
    require_vision: bool = False
    require_json_output: bool = False
    require_tool_use: bool = False
    preferred_providers: list[str] = Field(default_factory=list)
    excluded_providers: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_execution_context(self) -> ExecutionContext:
        return ExecutionContext(
            task_type=self.task_type,
            required_capabilities=self.required_capabilities,
            preferred_capabilities=self.preferred_capabilities,
            max_tokens=self.max_tokens,
            max_cost=self.max_cost,
            require_offline=self.require_offline,
            require_streaming=self.require_streaming,
            require_vision=self.require_vision,
            require_json=self.require_json_output,
            require_tool_use=self.require_tool_use,
            timeout_seconds=self.metadata.get("timeout", 120.0),
            metadata=self.metadata,
        )


class RoutingDecision(BaseModel):
    """The result of a routing decision — which provider/model to use."""

    provider_name: str = ""
    model_name: str = ""
    reason: str = ""
    matched_capabilities: list[str] = Field(default_factory=list)
    unmatched_capabilities: list[str] = Field(default_factory=list)
    estimated_cost: float = 0.0
    attempt_number: int = 1
    total_attempts: int = 1
    fallback_chain: list[str] = Field(default_factory=list)


class ModelResponse(BaseModel):
    """Response from executing a routed model request."""

    id: str = Field(default_factory=lambda: f"resp-{uuid4().hex[:12]}")
    request_id: str = ""
    content: str = ""
    model: str = ""
    provider: str = ""
    usage: dict[str, int] = Field(default_factory=dict)
    routing_decision: RoutingDecision = Field(default_factory=RoutingDecision)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class RoutingMetrics(BaseModel):
    """Aggregated metrics about routing operations."""

    total_requests: int = 0
    successful_routes: int = 0
    failed_routes: int = 0
    fallbacks_used: int = 0
    average_routing_ms: float = 0.0
    provider_counts: dict[str, int] = Field(default_factory=dict)
    model_counts: dict[str, int] = Field(default_factory=dict)
    task_counts: dict[str, int] = Field(default_factory=dict)
