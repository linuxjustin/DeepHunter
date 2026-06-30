"""Tests for AI Session management with conversation memory."""

from __future__ import annotations

from deephunter.llm.session import (
    AISession,
    AISessionManager,
    ContextLevel,
    Message,
    SessionConfig,
    SessionStatus,
)


class TestAISession:
    def test_create_session(self) -> None:
        session = AISession(target_id="tgt-1", investigation_id="inv-1")
        assert session.id.startswith("sess-")
        assert session.target_id == "tgt-1"
        assert session.investigation_id == "inv-1"
        assert session.status == SessionStatus.ACTIVE

    def test_add_user_message(self) -> None:
        session = AISession()
        msg = session.add_user_message("Hello, analyze this API")
        assert msg.role == "user"
        assert msg.content == "Hello, analyze this API"
        assert len(session._messages) == 1

    def test_add_assistant_message(self) -> None:
        session = AISession()
        session.add_user_message("Hello")
        msg = session.add_assistant_message("I can help analyze your API", model="gpt-4o", tokens_used=20)
        assert msg.role == "assistant"
        assert msg.model == "gpt-4o"
        assert msg.tokens_used == 20

    def test_add_system_message(self) -> None:
        session = AISession()
        msg = session.add_system_message("You are a security researcher")
        assert msg.role == "system"
        assert "security researcher" in msg.content

    def test_add_tool_result(self) -> None:
        session = AISession()
        msg = session.add_tool_result("call_123", "SQL injection found in login")
        assert msg.role == "tool"
        assert len(msg.tool_results) == 1
        assert msg.tool_results[0]["id"] == "call_123"

    def test_get_messages(self) -> None:
        session = AISession()
        session.add_system_message("You are helpful")
        session.add_user_message("Hello")
        session.add_assistant_message("Hi there")
        msgs = session.get_messages()
        assert len(msgs) == 3
        msgs_no_system = session.get_messages(include_system=False)
        assert len(msgs_no_system) == 2

    def test_get_recent_messages(self) -> None:
        session = AISession()
        for i in range(15):
            session.add_user_message(f"Message {i}")
        recent = session.get_recent_messages(count=5)
        assert len(recent) == 5

    def test_get_context_window(self) -> None:
        session = AISession(config=SessionConfig(max_total_tokens=50))
        for i in range(10):
            session.add_message(role="user", content=f"Message {i}" * 10, tokens_used=20)
        window = session.get_context_window()
        assert len(window) <= 3

    def test_get_stats(self) -> None:
        session = AISession()
        session.add_user_message("Hello")
        session.add_assistant_message("Hi")
        stats = session.get_stats()
        assert stats["total_messages"] == 2
        assert stats["user_messages"] == 1
        assert stats["assistant_messages"] == 1
        assert stats["status"] == "active"

    def test_archive(self) -> None:
        session = AISession()
        session.archive()
        assert session.status == SessionStatus.ARCHIVED

    def test_conversation_turns(self) -> None:
        session = AISession()
        session.add_user_message("Hello")
        session.add_assistant_message("Hi")
        session.add_user_message("How are you?")
        turns = session.get_conversation_turns(max_turns=2)
        assert len(turns) == 4


class TestAISessionManager:
    def test_create_session(self) -> None:
        manager = AISessionManager()
        session = manager.create_session(target_id="tgt-1")
        assert session.target_id == "tgt-1"
        assert session.id in manager._sessions

    def test_get_session(self) -> None:
        manager = AISessionManager()
        created = manager.create_session()
        retrieved = manager.get_session(created.id)
        assert retrieved is created

    def test_delete_session(self) -> None:
        manager = AISessionManager()
        session = manager.create_session()
        result = manager.delete_session(session.id)
        assert result is True
        assert manager.get_session(session.id) is None

    def test_list_sessions(self) -> None:
        manager = AISessionManager()
        s1 = manager.create_session(target_id="tgt-1")
        s2 = manager.create_session(target_id="tgt-2")
        s3 = manager.create_session(target_id="tgt-1")
        all_sessions = manager.list_sessions()
        assert len(all_sessions) == 3
        tgt1_sessions = manager.list_sessions(target_id="tgt-1")
        assert len(tgt1_sessions) == 2

    def test_list_sessions_by_status(self) -> None:
        manager = AISessionManager()
        s1 = manager.create_session()
        s1.archive()
        s2 = manager.create_session()
        active = manager.list_sessions(status=SessionStatus.ACTIVE)
        archived = manager.list_sessions(status=SessionStatus.ARCHIVED)
        assert len(active) == 1
        assert len(archived) == 1

    def test_cleanup_expired(self) -> None:
        manager = AISessionManager()
        session = manager.create_session()
        deleted = manager.cleanup_expired(max_age_hours=0)
        assert deleted == 0