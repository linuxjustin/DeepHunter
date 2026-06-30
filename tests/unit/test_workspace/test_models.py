"""Tests for workspace models."""

from __future__ import annotations

from deephunter.workspace.models import (
    AIConversation,
    Attachment,
    AttachmentType,
    Asset,
    ConversationMessage,
    ConversationRole,
    Note,
    Project,
    ProjectStatus,
    Report,
    ReportFormat,
    Target,
    TargetStatus,
    TargetType,
    Tag,
    TimelineEvent,
    Workspace,
    WorkspaceState,
)


class TestWorkspaceModels:
    def test_create_workspace(self) -> None:
        ws = Workspace(name="Test Workspace", description="A test workspace")
        assert ws.name == "Test Workspace"
        assert ws.id.startswith("ws-")
        assert isinstance(ws.state, WorkspaceState)

    def test_create_project(self) -> None:
        ws = Workspace(name="Test")
        project = Project(name="Bug Bounty Program", description="HackerOne program")
        ws.state.projects.append(project)
        assert len(ws.state.projects) == 1
        assert project.id.startswith("prj-")

    def test_create_target(self) -> None:
        ws = Workspace(name="Test")
        from deephunter.workspace.models import TargetScope, ScopeEntry
        target = Target(project_id="prj-1", name="API Server", url="https://api.example.com", target_type=TargetType.API)
        ws.state.targets.append(target)
        assert len(ws.state.targets) == 1
        assert target.target_type == TargetType.API
        assert target.status == TargetStatus.CREATED

    def test_create_conversation(self) -> None:
        ws = Workspace(name="Test")
        conv = AIConversation(target_id="tgt-1", title="Security Review")
        ws.state.conversations.append(conv)
        assert len(ws.state.conversations) == 1
        assert conv.title == "Security Review"

    def test_add_message_to_conversation(self) -> None:
        conv = AIConversation(target_id="tgt-1")
        msg = ConversationMessage(role=ConversationRole.USER, content="Hello, analyze this API")
        conv.messages.append(msg)
        assert len(conv.messages) == 1
        assert conv.messages[0].role == ConversationRole.USER

    def test_create_report(self) -> None:
        ws = Workspace(name="Test")
        report = Report(
            target_id="tgt-1",
            title="SQL Injection Findings",
            format=ReportFormat.MARKDOWN,
            content="# SQL Injection\n\nFound in login endpoint",
            findings_count=3,
            severity_counts={"critical": 1, "high": 2},
        )
        ws.state.reports.append(report)
        assert len(ws.state.reports) == 1
        assert report.format == ReportFormat.MARKDOWN

    def test_workspace_serialization(self) -> None:
        ws = Workspace(name="Test", description="Description")
        project = Project(name="Project 1")
        ws.state.projects.append(project)
        data = ws.model_dump_for_storage()
        assert data["name"] == "Test"
        assert len(data["state"]["projects"]) == 1