"""Investigation Notebook Manager.

Manages the lifecycle of investigation notebook entries including CRUD
operations, search, filtering, and export.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from deephunter.investigation.notebook.models import (
    NoteStatus,
    NoteType,
    NotebookEntry,
    NotebookState,
    NotebookSummary,
)

from deephunter.utils import get_logger

logger = get_logger(__name__)


class NotebookManager:
    """Manages investigation notebook entries."""

    def __init__(self, state: NotebookState) -> None:
        self._state = state

    @classmethod
    def new(cls, target_id: str, investigation_session_id: str = "") -> NotebookManager:
        state = NotebookState(
            target_id=target_id,
            investigation_session_id=investigation_session_id,
        )
        return cls(state)

    @property
    def state(self) -> NotebookState:
        return self._state

    def add_entry(
        self,
        entry_type: NoteType,
        title: str,
        content: str = "",
        author_id: str = "",
        tags: list[str] | None = None,
        status: NoteStatus = NoteStatus.ACTIVE,
        severity: str = "",
        confidence: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> NotebookEntry:
        entry = NotebookEntry(
            target_id=self._state.target_id,
            investigation_session_id=self._state.investigation_session_id,
            entry_type=entry_type,
            title=title,
            content=content,
            author_id=author_id,
            tags=tags or [],
            status=status,
            severity=severity,
            confidence=confidence,
            metadata=metadata or {},
        )
        self._state.entries.append(entry)
        self._state.updated_at = datetime.now(UTC)
        return entry

    def add_research_note(self, title: str, content: str, **kwargs: Any) -> NotebookEntry:
        return self.add_entry(NoteType.RESEARCH_NOTE, title, content, **kwargs)

    def add_observation(self, title: str, content: str, **kwargs: Any) -> NotebookEntry:
        return self.add_entry(NoteType.OBSERVATION, title, content, **kwargs)

    def add_question(self, title: str, content: str = "", **kwargs: Any) -> NotebookEntry:
        return self.add_entry(NoteType.QUESTION, title, content, **kwargs)

    def add_hypothesis_ref(self, hypothesis_id: str, title: str, status: str, **kwargs: Any) -> NotebookEntry:
        entry = self.add_entry(NoteType.HYPOTHESIS, title, "", **kwargs)
        entry.linked_hypothesis_ids.append(hypothesis_id)
        return entry

    def add_evidence_ref_entry(self, evidence_id: str, title: str, ref_type: str, **kwargs: Any) -> NotebookEntry:
        entry = self.add_entry(NoteType.EVIDENCE_REF, title, "", **kwargs)
        entry.linked_evidence_ids.append(evidence_id)
        return entry

    def add_interesting_url(self, url: str, title: str = "", description: str = "", **kwargs: Any) -> NotebookEntry:
        return self.add_entry(NoteType.INTERESTING_URL, title or url, description, **kwargs)

    def add_interesting_parameter(self, param_name: str, endpoint_url: str = "", **kwargs: Any) -> NotebookEntry:
        title = f"Interesting parameter: {param_name}"
        content = f"Parameter: {param_name}\nEndpoint: {endpoint_url}"
        return self.add_entry(NoteType.INTERESTING_PARAMETER, title, content, **kwargs)

    def add_interesting_technology(self, tech_name: str, category: str = "", **kwargs: Any) -> NotebookEntry:
        title = f"Interesting technology: {tech_name}"
        content = f"Technology: {tech_name}\nCategory: {category}"
        return self.add_entry(NoteType.INTERESTING_TECHNOLOGY, title, content, **kwargs)

    def add_interesting_auth_flow(self, flow_type: str, description: str = "", **kwargs: Any) -> NotebookEntry:
        title = f"Auth flow: {flow_type}"
        return self.add_entry(NoteType.INTERESTING_AUTH_FLOW, title, description, **kwargs)

    def add_interesting_api(self, api_name: str, base_url: str = "", **kwargs: Any) -> NotebookEntry:
        title = f"API: {api_name}"
        content = f"API: {api_name}\nBase URL: {base_url}"
        return self.add_entry(NoteType.INTERESTING_API, title, content, **kwargs)

    def add_manual_finding(self, title: str, content: str, severity: str = "", **kwargs: Any) -> NotebookEntry:
        return self.add_entry(NoteType.MANUAL_FINDING, title, content, severity=severity, **kwargs)

    def add_reference(self, title: str, url: str = "", **kwargs: Any) -> NotebookEntry:
        content = f"Reference: {title}\nURL: {url}"
        entry = self.add_entry(NoteType.REFERENCE, title, content, **kwargs)
        entry.references.append(url)
        return entry

    def update_entry(self, entry_id: str, **updates: Any) -> NotebookEntry | None:
        for entry in self._state.entries:
            if entry.id == entry_id:
                for key, value in updates.items():
                    if hasattr(entry, key):
                        setattr(entry, key, value)
                entry.updated_at = datetime.now(UTC)
                self._state.updated_at = datetime.now(UTC)
                return entry
        return None

    def archive_entry(self, entry_id: str) -> bool:
        entry = self.update_entry(entry_id, status=NoteStatus.ARCHIVED, archived_at=datetime.now(UTC))
        return entry is not None

    def flag_entry(self, entry_id: str) -> bool:
        entry = self.update_entry(entry_id, status=NoteStatus.FLAGGED)
        return entry is not None

    def get_entry(self, entry_id: str) -> NotebookEntry | None:
        for entry in self._state.entries:
            if entry.id == entry_id:
                return entry
        return None

    def get_entries_by_type(self, entry_type: NoteType) -> list[NotebookEntry]:
        return [e for e in self._state.entries if e.entry_type == entry_type]

    def get_entries_by_status(self, status: NoteStatus) -> list[NotebookEntry]:
        return [e for e in self._state.entries if e.status == status]

    def get_entries_by_tag(self, tag: str) -> list[NotebookEntry]:
        return [e for e in self._state.entries if tag in e.tags]

    def get_flagged_entries(self) -> list[NotebookEntry]:
        return self.get_entries_by_status(NoteStatus.FLAGGED)

    def get_active_entries(self) -> list[NotebookEntry]:
        return self.get_entries_by_status(NoteStatus.ACTIVE)

    def search_entries(self, query: str) -> list[NotebookEntry]:
        q = query.lower()
        return [
            e for e in self._state.entries
            if q in e.title.lower() or q in e.content.lower() or q in " ".join(e.tags).lower()
        ]

    def link_evidence(self, entry_id: str, evidence_id: str) -> bool:
        entry = self.get_entry(entry_id)
        if entry and evidence_id not in entry.linked_evidence_ids:
            entry.linked_evidence_ids.append(evidence_id)
            entry.updated_at = datetime.now(UTC)
            return True
        return False

    def link_hypothesis(self, entry_id: str, hypothesis_id: str) -> bool:
        entry = self.get_entry(entry_id)
        if entry and hypothesis_id not in entry.linked_hypothesis_ids:
            entry.linked_hypothesis_ids.append(hypothesis_id)
            entry.updated_at = datetime.now(UTC)
            return True
        return False

    def link_task(self, entry_id: str, task_id: str) -> bool:
        entry = self.get_entry(entry_id)
        if entry and task_id not in entry.linked_task_ids:
            entry.linked_task_ids.append(task_id)
            entry.updated_at = datetime.now(UTC)
            return True
        return False

    def get_summary(self) -> NotebookSummary:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        flagged = 0
        archived = 0

        for entry in self._state.entries:
            t = entry.entry_type.value
            by_type[t] = by_type.get(t, 0) + 1
            s = entry.status.value
            by_status[s] = by_status.get(s, 0) + 1
            if entry.status == NoteStatus.FLAGGED:
                flagged += 1
            elif entry.status == NoteStatus.ARCHIVED:
                archived += 1

        return NotebookSummary(
            total_entries=len(self._state.entries),
            entries_by_type=by_type,
            entries_by_status=by_status,
            total_evidence_refs=len(self._state.evidence_refs),
            total_endpoint_refs=len(self._state.endpoint_refs),
            total_parameter_refs=len(self._state.parameter_refs),
            total_technology_refs=len(self._state.technology_refs),
            total_auth_flow_refs=len(self._state.auth_flow_refs),
            total_api_refs=len(self._state.api_refs),
            flagged_entries=flagged,
            archived_entries=archived,
        )

    def export_to_dict(self) -> dict[str, Any]:
        return self._state.model_dump_for_storage()

    def export_to_markdown(self) -> str:
        lines = ["# Investigation Notebook\n"]
        for entry in self._state.entries:
            lines.append(f"## [{entry.entry_type.value}] {entry.title}\n")
            if entry.content:
                lines.append(f"{entry.content}\n")
            if entry.tags:
                lines.append(f"Tags: {', '.join(entry.tags)}\n")
            lines.append(f"_Created: {entry.created_at.isoformat()}_\n\n")
        return "\n".join(lines)
