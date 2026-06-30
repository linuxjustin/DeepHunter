"""Tests for Investigation Notebook models and manager."""

from __future__ import annotations

from deephunter.investigation.notebook import (
    NotebookManager,
    NotebookEntry,
    NotebookState,
    NotebookSummary,
    NoteType,
    NoteStatus,
)
from deephunter.investigation.notebook.models import (
    APIRef,
    AuthFlowRef,
    EndpointRef,
    EvidenceRef,
    EvidenceRefType,
    HypothesisRef,
    ParameterRef,
    TechnologyRef,
)


class TestNotebookManager:
    def test_new_notebook(self) -> None:
        manager = NotebookManager.new("tgt-123", "inv-456")
        assert manager.state.target_id == "tgt-123"
        assert manager.state.investigation_session_id == "inv-456"

    def test_add_research_note(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_research_note("Initial Recon", "Found the login page at /login")
        assert entry.title == "Initial Recon"
        assert entry.entry_type == NoteType.RESEARCH_NOTE
        assert entry.target_id == "tgt-1"

    def test_add_observation(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_observation("Tech Fingerprint", "Server: nginx 1.20")
        assert entry.entry_type == NoteType.OBSERVATION

    def test_add_question(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_question("Admin panel location?", "Where is the admin panel?")
        assert entry.entry_type == NoteType.QUESTION
        assert entry.status == NoteStatus.ACTIVE

    def test_add_interesting_url(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_interesting_url("https://api.example.com/admin", "Potential admin URL")
        assert entry.entry_type == NoteType.INTERESTING_URL
        assert "admin" in entry.title

    def test_add_interesting_url_no_title(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_interesting_url("https://api.example.com/admin")
        assert "api.example.com" in entry.title

    def test_add_manual_finding(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_manual_finding("Reflected XSS", "XSS in search param", severity="high")
        assert entry.entry_type == NoteType.MANUAL_FINDING
        assert entry.severity == "high"

    def test_add_reference(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_reference("OWASP XSS", "https://owasp.org/www-community/attacks/xss/")
        assert entry.entry_type == NoteType.REFERENCE
        assert "https://owasp.org" in entry.references[0]

    def test_update_entry(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_research_note("Title", "Content")
        updated = manager.update_entry(entry.id, title="New Title", content="New Content")
        assert updated is not None
        assert updated.title == "New Title"
        assert updated.content == "New Content"

    def test_archive_entry(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_research_note("To Archive", "Content")
        result = manager.archive_entry(entry.id)
        assert result is True
        e = manager.get_entry(entry.id)
        assert e is not None
        assert e.status == NoteStatus.ARCHIVED

    def test_flag_entry(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_research_note("Important", "Content")
        manager.flag_entry(entry.id)
        e = manager.get_entry(entry.id)
        assert e is not None
        assert e.status == NoteStatus.FLAGGED

    def test_get_entries_by_type(self) -> None:
        manager = NotebookManager.new("tgt-1")
        manager.add_research_note("Note 1", "Content")
        manager.add_observation("Obs 1", "Content")
        manager.add_research_note("Note 2", "Content")
        notes = manager.get_entries_by_type(NoteType.RESEARCH_NOTE)
        assert len(notes) == 2
        obs = manager.get_entries_by_type(NoteType.OBSERVATION)
        assert len(obs) == 1

    def test_search_entries(self) -> None:
        manager = NotebookManager.new("tgt-1")
        manager.add_research_note("SQL Injection", "Test for SQLi")
        manager.add_research_note("XSS Finding", "Test for XSS")
        results = manager.search_entries("SQL")
        assert len(results) == 1
        assert "SQL Injection" in results[0].title

    def test_link_evidence(self) -> None:
        manager = NotebookManager.new("tgt-1")
        entry = manager.add_research_note("Finding", "Content")
        result = manager.link_evidence(entry.id, "ev-123")
        assert result is True
        e = manager.get_entry(entry.id)
        assert e is not None
        assert "ev-123" in e.linked_evidence_ids

    def test_get_summary(self) -> None:
        manager = NotebookManager.new("tgt-1")
        manager.add_research_note("Note", "Content")
        manager.add_observation("Obs", "Content")
        manager.flag_entry(manager.add_research_note("Flagged", "Content").id)
        summary = manager.get_summary()
        assert summary.total_entries == 3
        assert summary.flagged_entries == 1

    def test_export_to_markdown(self) -> None:
        manager = NotebookManager.new("tgt-1")
        manager.add_research_note("Test Note", "Some content here")
        md = manager.export_to_markdown()
        assert "# Investigation Notebook" in md
        assert "Test Note" in md
        assert "Some content here" in md


class TestNotebookModels:
    def test_notebook_entry_defaults(self) -> None:
        entry = NotebookEntry(target_id="tgt-1", entry_type=NoteType.RESEARCH_NOTE, title="Test")
        assert entry.status == NoteStatus.ACTIVE
        assert entry.id.startswith("nb-")
        assert entry.confidence == 0.0

    def test_notebook_entry_with_links(self) -> None:
        entry = NotebookEntry(
            target_id="tgt-1",
            entry_type=NoteType.HYPOTHESIS,
            title="IDOR Hypothesis",
            linked_evidence_ids=["ev-1", "ev-2"],
            linked_hypothesis_ids=["hyp-1"],
            tags=["auth", "idor"],
        )
        assert len(entry.linked_evidence_ids) == 2
        assert "auth" in entry.tags

    def test_evidence_ref(self) -> None:
        ref = EvidenceRef(
            evidence_id="ev-1",
            ref_type=EvidenceRefType.HTTP_EXCHANGE,
            title="Login POST request",
            source="Burp Suite",
        )
        assert ref.ref_type == EvidenceRefType.HTTP_EXCHANGE
        assert "Login" in ref.title

    def test_endpoint_ref(self) -> None:
        ref = EndpointRef(url="https://api.example.com/users", method="POST", path="/users")
        assert ref.method == "POST"
        assert "example.com" in ref.url

    def test_parameter_ref(self) -> None:
        ref = ParameterRef(name="user_id", location="query", endpoint_url="/users")
        assert ref.name == "user_id"
        assert ref.location == "query"

    def test_technology_ref(self) -> None:
        ref = TechnologyRef(name="React", category="frontend", version="18.0.0", confidence=0.95)
        assert ref.confidence == 0.95
        assert ref.category == "frontend"

    def test_hypothesis_ref(self) -> None:
        ref = HypothesisRef(
            hypothesis_id="hyp-1",
            title="JWT weak secret",
            status="proposed",
            confidence=0.7,
            bug_classes=["auth_bypass"],
        )
        assert ref.confidence == 0.7
        assert "auth_bypass" in ref.bug_classes