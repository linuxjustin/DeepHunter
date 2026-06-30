"""Evidence Manager — structured evidence collection and storage.

Composes with the existing ``InvestigationSession.add_evidence()`` method
which stores evidence in the reasoning graph. This manager adds workflow-level
evidence tracking (tags, source steps, bulk operations).
"""

from __future__ import annotations

from typing import Any

from deephunter.investigation.models import (
    EvidenceRecord,
    EvidenceType,
    InvestigationSessionState,
)


class EvidenceManager:
    """Manages structured evidence collection across an investigation.

    Usage:
        manager = EvidenceManager(state)
        ev = manager.record_evidence("Found login page",
                                     "200 OK on /login",
                                     EvidenceType.HTTP_RESPONSE,
                                     source_step="recon")
        all_http = manager.get_by_type(EvidenceType.HTTP_RESPONSE)
    """

    def __init__(self, state: InvestigationSessionState) -> None:
        self._state = state

    def record_evidence(
        self,
        title: str,
        content: str,
        evidence_type: EvidenceType = EvidenceType.OTHER,
        source_step: str = "",
        source_task: str = "",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Record a piece of structured evidence.

        Args:
            title: Short descriptive title.
            content: The evidence data.
            evidence_type: Type of evidence.
            source_step: Which workflow step generated this.
            source_task: Which task generated this.
            tags: Optional classification tags.
            metadata: Optional structured metadata.

        Returns:
            The created EvidenceRecord.
        """
        record = EvidenceRecord(
            title=title,
            evidence_type=evidence_type,
            content=content,
            source_step=source_step,
            source_task=source_task,
            tags=tags or [],
            metadata=metadata or {},
        )
        self._state.evidence.append(record)
        return record

    def get_by_id(self, evidence_id: str) -> EvidenceRecord | None:
        for ev in self._state.evidence:
            if ev.id == evidence_id:
                return ev
        return None

    def get_by_type(self, evidence_type: EvidenceType) -> list[EvidenceRecord]:
        return [ev for ev in self._state.evidence if ev.evidence_type == evidence_type]

    def get_by_step(self, step_id: str) -> list[EvidenceRecord]:
        return [ev for ev in self._state.evidence if ev.source_step == step_id]

    def get_by_task(self, task_id: str) -> list[EvidenceRecord]:
        return [ev for ev in self._state.evidence if ev.source_task == task_id]

    def get_by_tag(self, tag: str) -> list[EvidenceRecord]:
        return [ev for ev in self._state.evidence if tag in ev.tags]

    def search(self, query: str) -> list[EvidenceRecord]:
        q = query.lower()
        return [
            ev for ev in self._state.evidence
            if q in ev.title.lower() or q in ev.content.lower()
        ]

    def count(self) -> int:
        return len(self._state.evidence)

    def delete(self, evidence_id: str) -> bool:
        for i, ev in enumerate(self._state.evidence):
            if ev.id == evidence_id:
                self._state.evidence.pop(i)
                return True
        return False

    def clear(self) -> None:
        self._state.evidence.clear()

    def export_all(self) -> list[dict[str, Any]]:
        return [ev.to_dict() for ev in self._state.evidence]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ev in self._state.evidence:
            counts[ev.evidence_type.value] = counts.get(ev.evidence_type.value, 0) + 1
        return counts
