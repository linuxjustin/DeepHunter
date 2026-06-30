"""Intelligence Manager for DeepHunter.

Manages the intelligence lifecycle including hypothesis enhancement,
evidence quality scoring, learning suggestions, pattern discovery,
knowledge curation, and reasoning traces.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from deephunter.intelligence.models import (
    AnalystNotes,
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
    IntelligenceState,
    KnowledgeCurationEntry,
    LearningSuggestion,
    LearningSuggestionType,
    PatternConfidence,
    PatternType,
    ReasoningStep,
    ReasoningStepType,
    ReasoningTrace,
)
from deephunter.utils import get_logger

logger = get_logger(__name__)


class IntelligenceManager:
    """Manages the full intelligence lifecycle for investigations."""

    def __init__(self, state: IntelligenceState) -> None:
        self._state = state

    @classmethod
    def new(cls, target_id: str = "", investigation_session_id: str = "", project_id: str = "") -> IntelligenceManager:
        state = IntelligenceState(
            target_id=target_id,
            investigation_session_id=investigation_session_id,
            project_id=project_id,
        )
        return cls(state)

    @property
    def state(self) -> IntelligenceState:
        return self._state

    def enhance_hypothesis(
        self,
        base_hypothesis_id: str,
        related_hypothesis_ids: list[str] | None = None,
        supporting_evidence_ids: list[str] | None = None,
        contradicting_evidence_ids: list[str] | None = None,
        alternative_hypothesis_ids: list[str] | None = None,
        related_asset_ids: list[str] | None = None,
        related_technology_ids: list[str] | None = None,
        related_sko_ids: list[str] | None = None,
    ) -> HypothesisEnhancement:
        links = EnhancedHypothesisLinks(
            related_hypothesis_ids=related_hypothesis_ids or [],
            supporting_evidence_ids=supporting_evidence_ids or [],
            contradicting_evidence_ids=contradicting_evidence_ids or [],
            alternative_hypothesis_ids=alternative_hypothesis_ids or [],
        )
        enhancement = HypothesisEnhancement(
            base_hypothesis_id=base_hypothesis_id,
            target_id=self._state.target_id,
            investigation_session_id=self._state.investigation_session_id,
            links=links,
            related_asset_ids=related_asset_ids or [],
            related_technology_ids=related_technology_ids or [],
            related_sko_ids=related_sko_ids or [],
        )
        self._state.hypothesis_enhancements.append(enhancement)
        self._state.updated_at = datetime.now(UTC)
        return enhancement

    def get_hypothesis_enhancement(self, base_hypothesis_id: str) -> HypothesisEnhancement | None:
        for enh in self._state.hypothesis_enhancements:
            if enh.base_hypothesis_id == base_hypothesis_id:
                return enh
        return None

    def update_hypothesis_outcome(
        self,
        base_hypothesis_id: str,
        outcome: HypothesisOutcome,
        notes: str = "",
        feedback: str = "",
    ) -> bool:
        enh = self.get_hypothesis_enhancement(base_hypothesis_id)
        if not enh:
            enh = self.enhance_hypothesis(base_hypothesis_id)
        enh.outcome = outcome
        enh.analyst_notes.final_notes = notes
        enh.analyst_notes.feedback = feedback
        enh.analyst_notes.updated_at = datetime.now(UTC)
        if outcome in (HypothesisOutcome.CONFIRMED, HypothesisOutcome.REFUTED):
            enh.resolved_at = datetime.now(UTC)
        self._state.updated_at = datetime.now(UTC)
        return True

    def set_hypothesis_review_status(
        self,
        base_hypothesis_id: str,
        status: HypothesisReviewStatus,
        notes: str = "",
    ) -> bool:
        enh = self.get_hypothesis_enhancement(base_hypothesis_id)
        if not enh:
            return False
        enh.review_status = status
        if status == HypothesisReviewStatus.REVIEWED:
            enh.reviewed_at = datetime.now(UTC)
        if notes:
            enh.analyst_notes.review_notes = notes
        self._state.updated_at = datetime.now(UTC)
        return True

    def add_ai_suggestion(self, base_hypothesis_id: str, suggestion: str) -> bool:
        enh = self.get_hypothesis_enhancement(base_hypothesis_id)
        if not enh:
            enh = self.enhance_hypothesis(base_hypothesis_id)
        enh.ai_suggestions.append(suggestion)
        self._state.updated_at = datetime.now(UTC)
        return True

    def set_evidence_quality(
        self,
        evidence_id: str,
        quality_level: EvidenceQualityLevel,
        source_type: EvidenceSource = EvidenceSource.OTHER,
        reliability: float = 0.5,
        freshness: float = 1.0,
        relevance: float = 0.5,
        provenance_chain: list[str] | None = None,
    ) -> EvidenceQuality:
        quality = EvidenceQuality(
            quality_level=quality_level,
            source_type=source_type,
            reliability_score=reliability,
            freshness_score=freshness,
            relevance_score=relevance,
            provenance_chain=provenance_chain or [],
        )
        quality.overall_score = quality.compute_overall_score()
        self._state.evidence_qualities[evidence_id] = quality
        self._state.updated_at = datetime.now(UTC)
        return quality

    def verify_evidence(
        self,
        evidence_id: str,
        status: EvidenceVerificationStatus,
        notes: str = "",
        verified_by: str = "",
        conflicting_ids: list[str] | None = None,
        supporting_ids: list[str] | None = None,
    ) -> bool:
        if evidence_id not in self._state.evidence_qualities:
            self.set_evidence_quality(evidence_id, EvidenceQualityLevel.MEDIUM)
        q = self._state.evidence_qualities[evidence_id]
        q.verification_status = status
        q.verification_notes = notes
        q.verified_by = verified_by
        q.verified_at = datetime.now(UTC)
        if conflicting_ids:
            q.conflicting_evidence_ids = conflicting_ids
        if supporting_ids:
            q.supporting_evidence_ids = supporting_ids
        self._state.updated_at = datetime.now(UTC)
        return True

    def get_evidence_quality(self, evidence_id: str) -> EvidenceQuality | None:
        return self._state.evidence_qualities.get(evidence_id)

    def get_avg_evidence_quality(self) -> float:
        if not self._state.evidence_qualities:
            return 0.0
        scores = [q.overall_score for q in self._state.evidence_qualities.values()]
        return round(sum(scores) / len(scores), 3)

    def create_learning_suggestion(
        self,
        suggestion_type: LearningSuggestionType,
        title: str,
        description: str,
        rationale: str = "",
        evidence: str = "",
        confidence: float = 0.5,
        priority: int = 5,
        tags: list[str] | None = None,
    ) -> LearningSuggestion:
        suggestion = LearningSuggestion(
            suggestion_type=suggestion_type,
            title=title,
            description=description,
            rationale=rationale,
            evidence=evidence,
            confidence=confidence,
            target_id=self._state.target_id,
            investigation_session_id=self._state.investigation_session_id,
            project_id=self._state.project_id,
            priority=priority,
            tags=tags or [],
        )
        self._state.learning_suggestions.append(suggestion)
        self._state.updated_at = datetime.now(UTC)
        return suggestion

    def get_pending_suggestions(self) -> list[LearningSuggestion]:
        return [s for s in self._state.learning_suggestions if s.curation_status == CurationStatus.DRAFT]

    def approve_suggestion(self, suggestion_id: str, reviewer_id: str, notes: str = "") -> bool:
        for sugg in self._state.learning_suggestions:
            if sugg.id == suggestion_id:
                sugg.curation_status = CurationStatus.APPROVED
                sugg.reviewer_id = reviewer_id
                sugg.review_notes = notes
                sugg.reviewed_at = datetime.now(UTC)
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def reject_suggestion(self, suggestion_id: str, reviewer_id: str, notes: str = "") -> bool:
        for sugg in self._state.learning_suggestions:
            if sugg.id == suggestion_id:
                sugg.curation_status = CurationStatus.DRAFT
                sugg.curator_id = reviewer_id
                sugg.review_notes = notes
                sugg.reviewed_at = datetime.now(UTC)
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def create_discovered_pattern(
        self,
        pattern_type: PatternType,
        name: str,
        description: str,
        pattern_data: dict[str, Any] | None = None,
        confidence: PatternConfidence = PatternConfidence.SPECULATIVE,
        locations: list[str] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> DiscoveredPattern:
        pattern = DiscoveredPattern(
            pattern_type=pattern_type,
            name=name,
            description=description,
            pattern_data=pattern_data or {},
            confidence=confidence,
            locations=locations or [],
            project_id=self._state.project_id,
            target_id=self._state.target_id,
            evidence_ids=evidence_ids or [],
        )
        self._state.discovered_patterns.append(pattern)
        self._state.updated_at = datetime.now(UTC)
        return pattern

    def increment_pattern_occurrence(self, pattern_id: str, location: str) -> bool:
        for pat in self._state.discovered_patterns:
            if pat.id == pattern_id:
                pat.occurrence_count += 1
                if location not in pat.locations:
                    pat.locations.append(location)
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def promote_pattern(self, pattern_id: str, curator_id: str) -> bool:
        for pat in self._state.discovered_patterns:
            if pat.id == pattern_id:
                pat.curation_status = CurationStatus.APPROVED
                pat.curator_id = curator_id
                pat.reviewed_at = datetime.now(UTC)
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def add_to_curation_queue(
        self,
        content_type: str,
        content_id: str,
        content_summary: str,
        change_description: str = "",
        change_rationale: str = "",
    ) -> KnowledgeCurationEntry:
        entry = KnowledgeCurationEntry(
            content_type=content_type,
            content_id=content_id,
            content_summary=content_summary,
            change_description=change_description,
            change_rationale=change_rationale,
            project_id=self._state.project_id,
            investigation_session_id=self._state.investigation_session_id,
        )
        self._state.curation_queue.append(entry)
        self._state.updated_at = datetime.now(UTC)
        return entry

    def update_curation_status(self, entry_id: str, status: CurationStatus, reviewer_id: str, notes: str = "") -> bool:
        for entry in self._state.curation_queue:
            if entry.id == entry_id:
                entry.previous_status = entry.status
                entry.status = status
                entry.reviewer_id = reviewer_id
                entry.review_notes = notes
                entry.reviewed_at = datetime.now(UTC)
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def create_reasoning_trace(
        self,
        hypothesis_id: str = "",
        steps: list[ReasoningStep] | None = None,
    ) -> ReasoningTrace:
        trace = ReasoningTrace(
            investigation_session_id=self._state.investigation_session_id,
            target_id=self._state.target_id,
            hypothesis_id=hypothesis_id,
            steps=steps or [],
        )
        self._state.reasoning_traces.append(trace)
        self._state.updated_at = datetime.now(UTC)
        return trace

    def add_reasoning_step(
        self,
        trace_id: str,
        step_type: ReasoningStepType,
        content: str,
        reasoning: str = "",
        alternatives: list[str] | None = None,
        selected: str = "",
    ) -> bool:
        for trace in self._state.reasoning_traces:
            if trace.id == trace_id:
                step = ReasoningStep(
                    step_type=step_type,
                    content=content,
                    reasoning=reasoning,
                    alternatives=alternatives or [],
                    selected_alternative=selected,
                )
                trace.steps.append(step)
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def set_trace_feedback(self, trace_id: str, feedback: str, rating: int) -> bool:
        for trace in self._state.reasoning_traces:
            if trace.id == trace_id:
                trace.feedback = feedback
                trace.feedback_rating = max(0, min(5, rating))
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def get_summary(self) -> dict[str, Any]:
        hypotheses = self._state.hypothesis_enhancements
        outcome_counts = {o.value: 0 for o in HypothesisOutcome}
        for h in hypotheses:
            outcome_counts[h.outcome.value] = outcome_counts.get(h.outcome.value, 0) + 1

        suggestions = self._state.learning_suggestions
        suggestion_counts = {
            "total": len(suggestions),
            "pending": sum(1 for s in suggestions if s.curation_status == CurationStatus.DRAFT),
            "approved": sum(1 for s in suggestions if s.curation_status == CurationStatus.APPROVED),
        }

        patterns = self._state.discovered_patterns
        pattern_counts = {
            "total": len(patterns),
            "pending": sum(1 for p in patterns if p.curation_status == CurationStatus.DRAFT),
            "promoted": sum(1 for p in patterns if p.curation_status == CurationStatus.APPROVED),
        }

        traces = self._state.reasoning_traces
        avg_quality = sum(t.quality_score for t in traces) / len(traces) if traces else 0.0
        avg_feedback = sum(t.feedback_rating for t in traces) / len(traces) if traces else 0.0

        evidence_qualities = list(self._state.evidence_qualities.values())
        high_quality = sum(1 for q in evidence_qualities if q.quality_level == EvidenceQualityLevel.HIGH)
        unverified = sum(1 for q in evidence_qualities if q.verification_status == EvidenceVerificationStatus.UNVERIFIED)

        return {
            "hypotheses": {
                "total": len(hypotheses),
                **outcome_counts,
            },
            "evidence_quality": {
                "avg_score": self.get_avg_evidence_quality(),
                "high_quality": high_quality,
                "unverified": unverified,
            },
            "learning_suggestions": suggestion_counts,
            "patterns": pattern_counts,
            "reasoning_traces": {
                "total": len(traces),
                "avg_quality": round(avg_quality, 3),
                "avg_feedback": round(avg_feedback, 2),
            },
        }

    def export_to_dict(self) -> dict[str, Any]:
        return self._state.model_dump(mode="json")