"""Tests for Intelligence module - evidence quality, hypothesis enhancement, learning, patterns, curation, traces."""

from __future__ import annotations

from deephunter.intelligence import (
    CurationStatus,
    DiscoveredPattern,
    EnhancedHypothesisLinks,
    EvidenceQuality,
    EvidenceQualityLevel,
    EvidenceSource,
    EvidenceVerificationStatus,
    HypothesisEnhancement,
    HypothesisOutcome,
    HypothesisReviewStatus,
    IntelligenceManager,
    KnowledgeCurationEntry,
    LearningSuggestion,
    LearningSuggestionType,
    PatternConfidence,
    PatternType,
    ReasoningStep,
    ReasoningStepType,
    ReasoningTrace,
)


class TestEvidenceQuality:
    def test_compute_overall_score(self) -> None:
        q = EvidenceQuality(
            quality_level=EvidenceQualityLevel.HIGH,
            reliability_score=0.9,
            freshness_score=0.8,
            relevance_score=0.7,
        )
        score = q.compute_overall_score()
        assert 0.0 <= score <= 1.0
        assert score > 0.5

    def test_quality_levels(self) -> None:
        assert EvidenceQualityLevel.HIGH.value == "high"
        assert EvidenceQualityLevel.LOW.value == "low"
        assert EvidenceQualityLevel.MEDIUM.value == "medium"
        assert EvidenceQualityLevel.UNVERIFIED.value == "unverified"

    def test_verification_status(self) -> None:
        assert EvidenceVerificationStatus.VERIFIED.value == "verified"
        assert EvidenceVerificationStatus.CONFLICTING.value == "conflicting"
        assert EvidenceVerificationStatus.DISPROVEN.value == "disproven"

    def test_evidence_source(self) -> None:
        assert EvidenceSource.RECON.value == "recon"
        assert EvidenceSource.MANUAL_TESTING.value == "manual_testing"
        assert EvidenceSource.AI_GENERATED.value == "ai_generated"


class TestHypothesisEnhancement:
    def test_create_enhancement(self) -> None:
        enh = HypothesisEnhancement(
            base_hypothesis_id="hyp-123",
            target_id="tgt-1",
        )
        assert enh.base_hypothesis_id == "hyp-123"
        assert enh.outcome == HypothesisOutcome.PENDING
        assert enh.review_status == HypothesisReviewStatus.DRAFT
        assert enh.id.startswith("hype-")

    def test_enhancement_with_links(self) -> None:
        links = EnhancedHypothesisLinks(
            related_hypothesis_ids=["hyp-1", "hyp-2"],
            supporting_evidence_ids=["ev-1"],
            contradicting_evidence_ids=["ev-2"],
            alternative_hypothesis_ids=["hyp-3"],
        )
        enh = HypothesisEnhancement(base_hypothesis_id="hyp-main", links=links)
        assert len(enh.links.related_hypothesis_ids) == 2
        assert len(enh.links.supporting_evidence_ids) == 1
        assert len(enh.links.alternative_hypothesis_ids) == 1


class TestIntelligenceManager:
    def test_create_manager(self) -> None:
        mgr = IntelligenceManager.new("tgt-1", "inv-1", "proj-1")
        assert mgr.state.target_id == "tgt-1"
        assert mgr.state.investigation_session_id == "inv-1"
        assert mgr.state.project_id == "proj-1"

    def test_enhance_hypothesis(self) -> None:
        mgr = IntelligenceManager.new()
        enh = mgr.enhance_hypothesis(
            base_hypothesis_id="hyp-123",
            related_hypothesis_ids=["hyp-456"],
            supporting_evidence_ids=["ev-1"],
        )
        assert enh.base_hypothesis_id == "hyp-123"
        assert "hyp-456" in enh.links.related_hypothesis_ids
        assert "ev-1" in enh.links.supporting_evidence_ids

    def test_update_hypothesis_outcome(self) -> None:
        mgr = IntelligenceManager.new()
        mgr.enhance_hypothesis("hyp-1")
        result = mgr.update_hypothesis_outcome("hyp-1", HypothesisOutcome.CONFIRMED, "Found SQLi", "AI suggested this")
        assert result is True
        enh = mgr.get_hypothesis_enhancement("hyp-1")
        assert enh is not None
        assert enh.outcome == HypothesisOutcome.CONFIRMED
        assert enh.analyst_notes.final_notes == "Found SQLi"

    def test_add_ai_suggestion(self) -> None:
        mgr = IntelligenceManager.new()
        mgr.enhance_hypothesis("hyp-1")
        mgr.add_ai_suggestion("hyp-1", "Consider IDOR in user profile endpoint")
        enh = mgr.get_hypothesis_enhancement("hyp-1")
        assert enh is not None
        assert len(enh.ai_suggestions) == 1

    def test_set_evidence_quality(self) -> None:
        mgr = IntelligenceManager.new()
        q = mgr.set_evidence_quality(
            "ev-1",
            quality_level=EvidenceQualityLevel.HIGH,
            source_type=EvidenceSource.RECON,
            reliability=0.9,
            freshness=1.0,
            relevance=0.8,
        )
        assert q.quality_level == EvidenceQualityLevel.HIGH
        assert q.overall_score > 0.5

    def test_verify_evidence(self) -> None:
        mgr = IntelligenceManager.new()
        mgr.set_evidence_quality("ev-1", EvidenceQualityLevel.MEDIUM)
        result = mgr.verify_evidence("ev-1", EvidenceVerificationStatus.VERIFIED, "Confirmed manually", "analyst-1")
        assert result is True
        q = mgr.get_evidence_quality("ev-1")
        assert q is not None
        assert q.verification_status == EvidenceVerificationStatus.VERIFIED

    def test_get_avg_evidence_quality(self) -> None:
        mgr = IntelligenceManager.new()
        mgr.set_evidence_quality("ev-1", EvidenceQualityLevel.HIGH)
        mgr.set_evidence_quality("ev-2", EvidenceQualityLevel.LOW)
        avg = mgr.get_avg_evidence_quality()
        assert 0.0 <= avg <= 1.0

    def test_create_learning_suggestion(self) -> None:
        mgr = IntelligenceManager.new()
        sugg = mgr.create_learning_suggestion(
            suggestion_type=LearningSuggestionType.PLANNER_IMPROVEMENT,
            title="Improve SQL injection detection",
            description="The planner should consider time-based blind SQLi",
            rationale="Found new variant in this target",
            confidence=0.7,
            priority=8,
        )
        assert sugg.suggestion_type == LearningSuggestionType.PLANNER_IMPROVEMENT
        assert sugg.curation_status == CurationStatus.DRAFT
        assert sugg.priority == 8

    def test_approve_suggestion(self) -> None:
        mgr = IntelligenceManager.new()
        sugg = mgr.create_learning_suggestion(
            LearningSuggestionType.METHODOLOGY_ADJUSTMENT,
            title="Add OAuth testing steps",
            description="Methodology should include OAuth flow testing",
        )
        result = mgr.approve_suggestion(sugg.id, "analyst-1", "Good suggestion")
        assert result is True
        assert sugg.curation_status == CurationStatus.APPROVED
        assert sugg.reviewer_id == "analyst-1"

    def test_create_discovered_pattern(self) -> None:
        mgr = IntelligenceManager.new()
        pat = mgr.create_discovered_pattern(
            pattern_type=PatternType.AUTHENTICATION_FLOW,
            name="JWT in Authorization header",
            description="JWT tokens passed in Authorization: Bearer header",
            pattern_data={"header_name": "Authorization", "scheme": "Bearer"},
            confidence=PatternConfidence.CONFIRMED,
            locations=["/api/login", "/api/profile"],
        )
        assert pat.pattern_type == PatternType.AUTHENTICATION_FLOW
        assert pat.occurrence_count == 1
        assert len(pat.locations) == 2

    def test_increment_pattern_occurrence(self) -> None:
        mgr = IntelligenceManager.new()
        pat = mgr.create_discovered_pattern(PatternType.API_DESIGN, "RESTful endpoints", "REST API structure")
        result = mgr.increment_pattern_occurrence(pat.id, "/api/v2/users")
        assert result is True
        assert pat.occurrence_count == 2
        assert "/api/v2/users" in pat.locations

    def test_add_to_curation_queue(self) -> None:
        mgr = IntelligenceManager.new()
        entry = mgr.add_to_curation_queue(
            content_type="sko",
            content_id="sko-123",
            content_summary="SQL Injection SKO update",
            change_description="Update detection technique",
            change_rationale="New variant discovered",
        )
        assert entry.content_type == "sko"
        assert entry.status == CurationStatus.DRAFT

    def test_create_reasoning_trace(self) -> None:
        mgr = IntelligenceManager.new()
        trace = mgr.create_reasoning_trace(hypothesis_id="hyp-1")
        assert trace.hypothesis_id == "hyp-1"
        assert trace.id.startswith("trace-")

    def test_add_reasoning_step(self) -> None:
        mgr = IntelligenceManager.new()
        trace = mgr.create_reasoning_trace("hyp-1")
        result = mgr.add_reasoning_step(
            trace_id=trace.id,
            step_type=ReasoningStepType.HYPOTHESIS,
            content="SQL injection in login endpoint",
            reasoning="The parameter is directly interpolated in query",
            alternatives=["No SQLi", "Second-order SQLi"],
            selected="SQL injection in login endpoint",
        )
        assert result is True
        assert len(trace.steps) == 1
        assert trace.steps[0].step_type == ReasoningStepType.HYPOTHESIS

    def test_get_summary(self) -> None:
        mgr = IntelligenceManager.new()
        mgr.enhance_hypothesis("hyp-1")
        mgr.enhance_hypothesis("hyp-2")
        mgr.update_hypothesis_outcome("hyp-1", HypothesisOutcome.CONFIRMED)
        summary = mgr.get_summary()
        assert summary["hypotheses"]["total"] == 2
        assert summary["hypotheses"]["confirmed"] == 1


class TestIntelligenceModels:
    def test_learning_suggestion_types(self) -> None:
        assert LearningSuggestionType.PLANNER_IMPROVEMENT.value == "planner_improvement"
        assert LearningSuggestionType.METHODOLOGY_ADJUSTMENT.value == "methodology_adjustment"
        assert LearningSuggestionType.KNOWLEDGE_PACK_SUGGESTION.value == "knowledge_pack_suggestion"
        assert LearningSuggestionType.WORKFLOW_REFINEMENT.value == "workflow_refinement"

    def test_pattern_types(self) -> None:
        assert PatternType.AUTHENTICATION_FLOW.value == "authentication_flow"
        assert PatternType.FRAMEWORK_STRUCTURE.value == "framework_structure"
        assert PatternType.API_DESIGN.value == "api_design"
        assert PatternType.TRUST_BOUNDARY.value == "trust_boundary"

    def test_curation_status(self) -> None:
        assert CurationStatus.DRAFT.value == "draft"
        assert CurationStatus.IN_REVIEW.value == "in_review"
        assert CurationStatus.APPROVED.value == "approved"
        assert CurationStatus.DEPRECATED.value == "deprecated"
        assert CurationStatus.ARCHIVED.value == "archived"

    def test_reasoning_step_types(self) -> None:
        assert ReasoningStepType.HYPOTHESIS.value == "hypothesis"
        assert ReasoningStepType.EVIDENCE.value == "evidence"
        assert ReasoningStepType.DECISION.value == "decision"
        assert ReasoningStepType.NEXT_ACTION.value == "next_action"
        assert ReasoningStepType.ALTERNATIVE.value == "alternative"
        assert ReasoningStepType.FEEDBACK.value == "feedback"

    def test_hypothesis_outcomes(self) -> None:
        assert HypothesisOutcome.PENDING.value == "pending"
        assert HypothesisOutcome.CONFIRMED.value == "confirmed"
        assert HypothesisOutcome.REFUTED.value == "refuted"
        assert HypothesisOutcome.INCONCLUSIVE.value == "inconclusive"
        assert HypothesisOutcome.SUPERSEDED.value == "superseded"

    def test_reasoning_trace_export(self) -> None:
        trace = ReasoningTrace(
            investigation_session_id="inv-1",
            hypothesis_id="hyp-1",
            steps=[
                ReasoningStep(
                    step_type=ReasoningStepType.HYPOTHESIS,
                    content="SQLi in login",
                    reasoning="Direct query interpolation",
                    confidence=0.8,
                )
            ],
            quality_score=0.75,
        )
        data = trace.model_dump(mode="json")
        assert data["investigation_session_id"] == "inv-1"
        assert data["hypothesis_id"] == "hyp-1"
        assert len(data["steps"]) == 1

    def test_knowledge_curation_entry(self) -> None:
        entry = KnowledgeCurationEntry(
            content_type="sko",
            content_id="sko-456",
            content_summary="Updated XSS knowledge",
            change_description="Add DOM XSS variant",
            change_rationale="Found in recent investigation",
        )
        assert entry.content_type == "sko"
        assert entry.content_id == "sko-456"
        assert entry.status == CurationStatus.DRAFT

    def test_discovered_pattern(self) -> None:
        pat = DiscoveredPattern(
            pattern_type=PatternType.SESSION_MANAGEMENT,
            name="Cookie-based session",
            description="Session ID in cookie header",
            pattern_data={"cookie_name": "SESSION_ID"},
            confidence=PatternConfidence.LIKELY,
            locations=["/login", "/logout"],
        )
        assert pat.pattern_type == PatternType.SESSION_MANAGEMENT
        assert pat.occurrence_count == 1