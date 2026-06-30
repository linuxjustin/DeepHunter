"""Investigation Notebook - Structured research artifact management."""

from deephunter.investigation.notebook.manager import NotebookManager
from deephunter.investigation.notebook.models import (
    APIRef,
    AuthFlowRef,
    EndpointRef,
    EvidenceRef,
    EvidenceRefType,
    HypothesisRef,
    NotebookChecklist,
    NotebookChecklistItem,
    NotebookEntry,
    NotebookState,
    NotebookSummary,
    NoteStatus,
    NoteType,
    ParameterRef,
    TechnologyRef,
)

__all__ = [
    "NotebookManager",
    "NotebookEntry",
    "NotebookState",
    "NotebookSummary",
    "NoteType",
    "NoteStatus",
    "HypothesisRef",
    "EvidenceRef",
    "EndpointRef",
    "ParameterRef",
    "TechnologyRef",
    "AuthFlowRef",
    "APIRef",
    "NotebookChecklist",
    "NotebookChecklistItem",
    "EvidenceRefType",
]