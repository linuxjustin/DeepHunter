"""Pydantic models for the Prompt Builder."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class PromptStyle(str, Enum):
    """Supported prompt styles for different investigation scenarios."""

    REASONING = "reasoning"
    PLANNING = "planning"
    CODE_REVIEW = "code_review"
    INVESTIGATION = "investigation"
    REPORTING = "reporting"
    LEARNING = "learning"


class PromptFormat(str, Enum):
    """Supported output formats for prompts."""

    MARKDOWN = "markdown"
    PLAIN_TEXT = "plain_text"
    JSON = "json"
    STRUCTURED = "structured"


class PromptMessageRole(str, Enum):
    """Role of a prompt message (analogous to LLM message roles)."""

    SYSTEM = "system"
    USER = "user"
    DEVELOPER = "developer"
    ASSISTANT = "assistant"
    TOOL = "tool"


class PromptMessage(BaseModel):
    """A single message within a prompt."""

    role: PromptMessageRole
    content: str
    name: str = ""


class PromptTemplate(BaseModel):
    """A configurable prompt template stored separately from code."""

    id: str = ""
    name: str = ""
    style: PromptStyle = PromptStyle.INVESTIGATION
    description: str = ""
    system_template: str = ""
    user_template: str = ""
    developer_template: str = ""
    variables: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptMetadata(BaseModel):
    """Metadata about a generated prompt."""

    model_config = ConfigDict(extra="allow")

    style: PromptStyle = PromptStyle.INVESTIGATION
    template_name: str = ""
    format: str = "markdown"
    model_adapter: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    tags: list[str] = Field(default_factory=list)


class PromptStatistics(BaseModel):
    """Statistics about a generated prompt."""

    total_messages: int = 0
    total_characters: int = 0
    estimated_tokens: int = 0
    estimated_cost: float = 0.0
    characters_by_role: dict[str, int] = Field(default_factory=dict)
    tokens_by_role: dict[str, int] = Field(default_factory=dict)


class PromptReference(BaseModel):
    """A reference included in a prompt."""

    reference_type: str = "other"
    identifier: str = ""
    title: str = ""
    url: str = ""
    description: str = ""


class Prompt(BaseModel):
    """The complete prompt produced by the PromptBuilder.

    Contains all messages, metadata, references, and statistics.
    """

    id: str = Field(default_factory=lambda: f"prompt-{uuid4().hex[:12]}")
    context_id: str = ""
    investigation_id: str = ""
    messages: list[PromptMessage] = Field(default_factory=list)
    metadata: PromptMetadata = Field(default_factory=PromptMetadata)
    statistics: PromptStatistics = Field(default_factory=PromptStatistics)
    references: list[PromptReference] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    def add_message(self, role: PromptMessageRole, content: str, name: str = "") -> None:
        self.messages.append(PromptMessage(role=role, content=content, name=name))

    def to_system_user(self) -> tuple[str, str]:
        """Extract the system and user messages as plain strings.

        Returns (system_message, user_message).  Returns (user_message, '')
        if no system message exists.
        """
        system = ""
        user = ""
        for msg in self.messages:
            if msg.role == PromptMessageRole.SYSTEM and not system:
                system = msg.content
            elif msg.role == PromptMessageRole.USER and not user:
                user = msg.content
        return system, user

    def recalculate(self) -> None:
        self.statistics.total_messages = len(self.messages)
        self.statistics.total_characters = sum(len(m.content) for m in self.messages)

        self.statistics.characters_by_role = {}
        self.statistics.tokens_by_role = {}
        total_tokens = 0

        for msg in self.messages:
            role = msg.role.value
            chars = len(msg.content)
            tokens = max(1, len(msg.content.split()) // 3 * 4)

            self.statistics.characters_by_role[role] = (
                self.statistics.characters_by_role.get(role, 0) + chars
            )
            self.statistics.tokens_by_role[role] = (
                self.statistics.tokens_by_role.get(role, 0) + tokens
            )
            total_tokens += tokens

        self.statistics.estimated_tokens = total_tokens or max(1, len(str(self.messages)) // 4)
        self.statistics.estimated_cost = self.statistics.estimated_tokens * 0.000015

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Prompt:
        return cls(**data)
