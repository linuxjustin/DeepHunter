"""Workspace manager for DeepHunter.

Manages the full workspace lifecycle including projects, targets,
investigations, evidence, reports, and AI conversations.

All changes are persisted to disk as JSON.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deephunter.utils.logging import get_logger

from .models import (
    AIConversation,
    Asset,
    Attachment,
    ConversationMessage,
    ConversationRole,
    Note,
    Project,
    ProjectStatus,
    Report,
    ReportFormat,
    Target,
    TargetStatus,
    Tag,
    TimelineEvent,
    Workspace,
    WorkspaceState,
)

logger = get_logger(__name__)


class WorkspaceManager:
    """Manages workspace operations and persistence.

    Usage::

        manager = WorkspaceManager("/path/to/workspaces")
        ws = manager.create_workspace("My Bug Bounty Program")
        project = ws.create_project("Vulnerability Research")
    """

    def __init__(self, workspace_dir: str | Path | None = None) -> None:
        self._workspace_dir = Path(workspace_dir) if workspace_dir else Path.home() / ".deephunter" / "workspaces"
        self._workspace_dir.mkdir(parents=True, exist_ok=True)
        self._current_workspace: Workspace | None = None

    @property
    def current_workspace(self) -> Workspace | None:
        return self._current_workspace

    def create_workspace(self, name: str, description: str = "") -> Workspace:
        ws = Workspace(name=name, description=description, state=WorkspaceState(workspace_id=f"ws-{uuid.uuid4().hex[:12]}", name=name))
        self._current_workspace = ws
        return ws

    def save_workspace(self, workspace: Workspace | None = None) -> Path:
        ws = workspace or self._current_workspace
        if ws is None:
            raise ValueError("No workspace to save")
        ws.updated_at = datetime.now(UTC)
        ws.state.updated_at = datetime.now(UTC)

        ws_path = self._workspace_dir / f"{ws.id}.json"
        ws_path.parent.mkdir(parents=True, exist_ok=True)
        ws_path.write_text(json.dumps(ws.model_dump_for_storage(), indent=2, default=str), "utf-8")
        logger.debug("Saved workspace %s to %s", ws.id, ws_path)
        return ws_path

    def load_workspace(self, workspace_id: str) -> Workspace:
        ws_path = self._workspace_dir / f"{workspace_id}.json"
        if not ws_path.exists():
            raise FileNotFoundError(f"Workspace not found: {workspace_id}")
        data = json.loads(ws_path.read_text("utf-8"))
        ws = Workspace.from_dict(data)
        self._current_workspace = ws
        return ws

    def load_workspace_by_path(self, path: str | Path) -> Workspace:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Workspace file not found: {p}")
        data = json.loads(p.read_text("utf-8"))
        ws = Workspace.from_dict(data)
        self._current_workspace = ws
        return ws

    def list_workspaces(self) -> list[dict[str, str]]:
        workspaces = []
        for ws_file in self._workspace_dir.glob("*.json"):
            try:
                data = json.loads(ws_file.read_text("utf-8"))
                workspaces.append({"id": data.get("id", ""), "name": data.get("name", ""), "path": str(ws_file)})
            except Exception:
                continue
        return workspaces

    def delete_workspace(self, workspace_id: str) -> bool:
        ws_path = self._workspace_dir / f"{workspace_id}.json"
        if ws_path.exists():
            ws_path.unlink()
            return True
        return False

    def create_project(self, name: str, description: str = "") -> Project:
        if self._current_workspace is None:
            self.create_workspace("Default Workspace")
        ws = self._current_workspace
        project = Project(name=name, description=description)
        ws.state.projects.append(project)
        self._emit_timeline_event(ws, "project_created", f"Project '{name}' created", project.id)
        logger.debug("Created project %s: %s", project.id, name)
        return project

    def get_project(self, project_id: str) -> Project | None:
        if self._current_workspace is None:
            return None
        for proj in self._current_workspace.state.projects:
            if proj.id == project_id:
                return proj
        return None

    def update_project(self, project_id: str, **kwargs: Any) -> Project | None:
        if self._current_workspace is None:
            return None
        for proj in self._current_workspace.state.projects:
            if proj.id == project_id:
                for key, value in kwargs.items():
                    if hasattr(proj, key):
                        setattr(proj, key, value)
                proj.updated_at = datetime.now(UTC)
                return proj
        return None

    def archive_project(self, project_id: str) -> Project | None:
        return self.update_project(project_id, status=ProjectStatus.ARCHIVED)

    def create_target(self, project_id: str, name: str, url: str, target_type: str = "web_application") -> Target | None:
        if self._current_workspace is None:
            return None
        from .models import TargetType
        target = Target(project_id=project_id, name=name, url=url, target_type=TargetType(target_type))
        self._current_workspace.state.targets.append(target)
        self._emit_timeline_event(self._current_workspace, "target_created", f"Target '{name}' added", target.id)
        logger.debug("Created target %s: %s", target.id, name)
        return target

    def get_target(self, target_id: str) -> Target | None:
        if self._current_workspace is None:
            return None
        for tgt in self._current_workspace.state.targets:
            if tgt.id == target_id:
                return tgt
        return None

    def update_target(self, target_id: str, **kwargs: Any) -> Target | None:
        if self._current_workspace is None:
            return None
        for tgt in self._current_workspace.state.targets:
            if tgt.id == target_id:
                for key, value in kwargs.items():
                    if hasattr(tgt, key):
                        setattr(tgt, key, value)
                tgt.updated_at = datetime.now(UTC)
                return tgt
        return None

    def create_tag(self, name: str, color: str = "#6366f1") -> Tag:
        if self._current_workspace is None:
            self.create_workspace("Default Workspace")
        tag = Tag(name=name, color=color)
        self._current_workspace.state.tags.append(tag)
        return tag

    def create_note(self, entity_type: str, entity_id: str, content: str, author_id: str = "") -> Note:
        if self._current_workspace is None:
            self.create_workspace("Default Workspace")
        note = Note(entity_type=entity_type, entity_id=entity_id, content=content, author_id=author_id)
        self._current_workspace.state.notes.append(note)
        return note

    def create_asset(self, target_id: str, asset_type: str, value: str, source: str = "") -> Asset:
        if self._current_workspace is None:
            raise ValueError("No workspace")
        asset = Asset(target_id=target_id, asset_type=asset_type, value=value, source=source)
        self._current_workspace.state.assets.append(asset)
        return asset

    def create_report(self, target_id: str, title: str, format: ReportFormat, content: str, findings_count: int = 0, severity_counts: dict[str, int] | None = None) -> Report:
        if self._current_workspace is None:
            raise ValueError("No workspace")
        report = Report(target_id=target_id, title=title, format=format, content=content, findings_count=findings_count, severity_counts=severity_counts or {})
        self._current_workspace.state.reports.append(report)
        return report

    def create_conversation(self, target_id: str, title: str = "New Conversation") -> AIConversation:
        if self._current_workspace is None:
            raise ValueError("No workspace")
        conv = AIConversation(target_id=target_id, title=title)
        self._current_workspace.state.conversations.append(conv)
        return conv

    def add_conversation_message(self, conversation_id: str, role: ConversationRole, content: str, model: str = "", tokens_used: int = 0) -> ConversationMessage | None:
        if self._current_workspace is None:
            return None
        for conv in self._current_workspace.state.conversations:
            if conv.id == conversation_id:
                msg = ConversationMessage(role=role, content=content, model=model, tokens_used=tokens_used)
                conv.messages.append(msg)
                conv.last_message_at = datetime.now(UTC)
                return msg
        return None

    def _emit_timeline_event(self, ws: Workspace, event_type: str, title: str, entity_id: str = "", severity: str = "info") -> None:
        event = TimelineEvent(project_id="", event_type=event_type, title=title, entity_id=entity_id, severity=severity)
        ws.state.timeline.append(event)