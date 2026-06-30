"""AI Session management with conversation memory.

Provides persistent conversation sessions with context window management,
workspace integration, and investigation context support.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SessionStatus(str, Enum):
    """Status of a conversation session."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    EXPIRED = "expired"


class ContextLevel(str, Enum):
    """Context level for session management."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    ENHANCED = "enhanced"
    COMPREHENSIVE = "comprehensive"


@dataclass
class Message:
    """A single message in a conversation session."""

    id: str = field(default_factory=lambda: f"msg-{uuid.uuid4().hex[:12]}")
    role: str = "user"
    content: str = ""
    model: str = ""
    tokens_used: int = 0
    tool_calls: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionConfig:
    """Configuration for a conversation session."""

    max_tokens_per_message: int = 16000
    max_total_tokens: int = 200000
    context_level: ContextLevel = ContextLevel.STANDARD
    system_prompt: str = ""
    workspace_context: str = ""
    investigation_context: str = ""
    planner_context: str = ""
    evidence_references: list[str] = field(default_factory=list)
    knowledge_references: list[str] = field(default_factory=list)
    include_timestamps: bool = True
    summarize_after_messages: int = 20


class AISession:
    """Manages a conversation session with memory and context."""

    def __init__(
        self,
        session_id: str | None = None,
        target_id: str = "",
        investigation_id: str = "",
        config: SessionConfig | None = None,
    ) -> None:
        self.id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
        self.target_id = target_id
        self.investigation_id = investigation_id
        self.config = config or SessionConfig()
        self.status = SessionStatus.ACTIVE
        self.created_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        self.last_message_at = datetime.now(UTC)
        self._messages: list[Message] = []
        self._token_counts: list[int] = []
        self._total_tokens = 0
        self._summary: str = ""

    def add_message(
        self,
        role: str,
        content: str,
        model: str = "",
        tokens_used: int = 0,
        tool_calls: list[dict] | None = None,
        attachments: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Message:
        msg = Message(
            role=role,
            content=content,
            model=model,
            tokens_used=tokens_used,
            tool_calls=tool_calls or [],
            attachments=attachments or [],
            metadata=metadata or {},
        )
        self._messages.append(msg)
        self._token_counts.append(tokens_used)
        self._total_tokens += tokens_used
        self.last_message_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        self._maybe_summarize()
        return msg

    def add_user_message(self, content: str, **kwargs: Any) -> Message:
        return self.add_message(role="user", content=content, **kwargs)

    def add_assistant_message(self, content: str, model: str = "", tokens_used: int = 0, tool_calls: list[dict] | None = None, **kwargs: Any) -> Message:
        return self.add_message(role="assistant", content=content, model=model, tokens_used=tokens_used, tool_calls=tool_calls, **kwargs)

    def add_system_message(self, content: str, **kwargs: Any) -> Message:
        return self.add_message(role="system", content=content, **kwargs)

    def add_tool_result(self, tool_call_id: str, content: str, **kwargs: Any) -> Message:
        msg = Message(role="tool", content=content, tool_results=[{"id": tool_call_id, "content": content}], **kwargs)
        self._messages.append(msg)
        self.updated_at = datetime.now(UTC)
        return msg

    def get_messages(self, include_system: bool = True) -> list[dict[str, Any]]:
        if include_system:
            return [self._msg_to_dict(m) for m in self._messages]
        return [self._msg_to_dict(m) for m in self._messages if m.role != "system"]

    def get_conversation_turns(self, max_turns: int = 10) -> list[dict[str, Any]]:
        turns = []
        i = len(self._messages) - 1
        while i >= 0 and len(turns) < max_turns * 2:
            msg = self._messages[i]
            if msg.role == "tool":
                i -= 1
                continue
            turns.insert(0, self._msg_to_dict(msg))
            i -= 1
        return turns

    def get_context_window(self, max_tokens: int | None = None) -> list[dict[str, Any]]:
        """Get messages fitting within token budget, oldest first."""
        limit = max_tokens or self.config.max_total_tokens
        result = []
        total = 0
        for msg in self._messages:
            tokens = msg.tokens_used or max(1, len(msg.content) // 4)
            if total + tokens <= limit:
                result.append(self._msg_to_dict(msg))
                total += tokens
            else:
                break
        return result

    def get_recent_messages(self, count: int = 10) -> list[dict[str, Any]]:
        recent = self._messages[-count:] if count > 0 else self._messages
        return [self._msg_to_dict(m) for m in recent]

    def get_summary(self) -> str:
        if self._summary:
            return self._summary
        if not self._messages:
            return ""
        return f"Conversation with {len(self._messages)} messages, {self._total_tokens} total tokens"

    def get_stats(self) -> dict[str, Any]:
        return {
            "session_id": self.id,
            "total_messages": len(self._messages),
            "total_tokens": self._total_tokens,
            "user_messages": sum(1 for m in self._messages if m.role == "user"),
            "assistant_messages": sum(1 for m in self._messages if m.role == "assistant"),
            "last_message_at": self.last_message_at.isoformat() if self.last_message_at else None,
            "status": self.status.value,
        }

    def archive(self) -> None:
        self.status = SessionStatus.ARCHIVED

    def _msg_to_dict(self, msg: Message) -> dict[str, Any]:
        d: dict[str, Any] = {"role": msg.role, "content": msg.content}
        if msg.model:
            d["model"] = msg.model
        if msg.tool_calls:
            d["tool_calls"] = msg.tool_calls
        if msg.tool_results:
            d["tool_results"] = msg.tool_results
        return d

    def _maybe_summarize(self) -> None:
        if len(self._messages) >= self.config.summarize_after_messages:
            recent = self._messages[-self.config.summarize_after_messages:]
            self._summary = f"Previous conversation covered: {[m.content[:50] + '...' for m in recent[:3]]}"


class AISessionManager:
    """Manages multiple AI sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, AISession] = {}

    def create_session(
        self,
        target_id: str = "",
        investigation_id: str = "",
        config: SessionConfig | None = None,
    ) -> AISession:
        session = AISession(
            target_id=target_id,
            investigation_id=investigation_id,
            config=config,
        )
        self._sessions[session.id] = session
        return session

    def get_session(self, session_id: str) -> AISession | None:
        return self._sessions.get(session_id)

    def delete_session(self, session_id: str) -> bool:
        return bool(self._sessions.pop(session_id, None))

    def list_sessions(
        self,
        target_id: str | None = None,
        status: SessionStatus | None = None,
    ) -> list[AISession]:
        result = list(self._sessions.values())
        if target_id:
            result = [s for s in result if s.target_id == target_id]
        if status:
            result = [s for s in result if s.status == status]
        return result

    def cleanup_expired(self, max_age_hours: int = 24) -> int:
        if max_age_hours <= 0:
            return 0
        cutoff = datetime.now(UTC).timestamp() - (max_age_hours * 3600)
        to_delete = [
            sid for sid, s in self._sessions.items()
            if s.last_message_at.timestamp() < cutoff and s.status == SessionStatus.ACTIVE
        ]
        for sid in to_delete:
            del self._sessions[sid]
        return len(to_delete)