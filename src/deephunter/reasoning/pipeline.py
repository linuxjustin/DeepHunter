"""Reasoning pipeline — stage-based investigation workflow.

Models how an experienced security researcher investigates a target:

    Observation → Evidence Collection → Hypothesis Generation
    → Prioritization → Manual Test Planning → Result Recording
    → Confidence Update → Pivot Generation → Finding Creation
    → Report Generation Hook

Every stage is independently testable.  The pipeline consumes
an ``InvestigationSession`` and mutates its state.
"""

from __future__ import annotations

import time

from deephunter.reasoning.models import ExperimentStatus
from deephunter.reasoning.session import InvestigationSession
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


def _status_in(status: object, *values: str) -> bool:
    """Check if an ExperimentStatus or string is in *values."""
    s = status.value if hasattr(status, "value") else str(status)
    return s in values


class ReasoningPipeline:
    """Stage-based reasoning pipeline.

    Operates on an ``InvestigationSession``, running configured
    stages in sequence.  Each stage reads and writes session state.

    Usage::

        session = InvestigationSession.new("https://example.com")
        pipeline = ReasoningPipeline()
        pipeline.run(session)
    """

    def __init__(self) -> None:
        self._stages: list[ReasoningStage] = [
            ObservationStage(),
            EvidenceCollectionStage(),
            HypothesisGenerationStage(),
            PrioritizationStage(),
            ExperimentPlanningStage(),
            ResultRecordingStage(),
            ConfidenceUpdateStage(),
            PivotGenerationStage(),
            FindingCreationStage(),
            ReportHookStage(),
        ]

    def run(self, session: InvestigationSession) -> PipelineReport:
        """Run the full reasoning pipeline on a session.

        Args:
            session: The investigation session to process.

        Returns:
            A ``PipelineReport`` with stage-level timing.
        """
        start = time.perf_counter()
        report = PipelineReport()

        for stage in self._stages:
            stage_start = time.perf_counter()
            try:
                stage.process(session)
            except Exception:
                logger.exception("Reasoning stage %s failed", stage.name)
            report.stage_times[stage.name] = time.perf_counter() - stage_start

        report.total_seconds = time.perf_counter() - start
        return report


class PipelineReport:
    """Timing and status report for a pipeline run."""

    def __init__(self) -> None:
        self.stage_times: dict[str, float] = {}
        self.total_seconds: float = 0.0


class ReasoningStage:
    """Base class for a reasoning pipeline stage."""

    name: str = ""

    def process(self, session: InvestigationSession) -> None:
        """Execute this stage on the given session.

        Args:
            session: The investigation session to mutate.
        """


class ObservationStage(ReasoningStage):
    """Stage 1: Create observations from session data.

    This stage seeds initial observations from the target description
    and any SKOs linked to the investigation.
    """

    name = "observation"

    def process(self, session: InvestigationSession) -> None:
        if session.state.observations:
            return

        if session.investigation.target:
            session.create_observation(
                obs_type="other",
                description=f"Target identified: {session.investigation.target}",
                source="pipeline",
            )


class EvidenceCollectionStage(ReasoningStage):
    """Stage 2: Collect initial evidence.

    Adds basic evidence for observations.  In future versions this
    will call external tools.
    """

    name = "evidence_collection"

    def process(self, session: InvestigationSession) -> None:
        for obs in session.state.observations:
            existing = [e for e in session.state.evidence if e.observation_id == obs.id]
            if not existing and obs.source:
                session.add_evidence(
                    observation_id=obs.id,
                    content=f"Source: {obs.source}",
                    source=obs.source,
                )


class HypothesisGenerationStage(ReasoningStage):
    """Stage 3: Generate hypotheses from observations.

    Creates initial hypotheses based on detected technologies,
    bug classes, and observation patterns.
    """

    name = "hypothesis_generation"

    def process(self, session: InvestigationSession) -> None:
        if session.state.hypotheses:
            return

        fp = session.state.technology_fingerprint
        tech_names = [t.value if hasattr(t, 'value') else str(t) for t in fp.technologies]
        if not tech_names:
            tech_names = ["web"]

        hyp = session.create_hypothesis(
            title=f"Investigate {', '.join(tech_names)} application",
            description=f"Systematic security review of {', '.join(tech_names)} application.",
            technologies=tech_names,
            observation_ids=[o.id for o in session.state.observations],
        )


class PrioritizationStage(ReasoningStage):
    """Stage 4: Prioritize hypotheses.

    Sorts hypotheses by initial confidence and bug class severity.
    """

    name = "prioritization"

    def process(self, session: InvestigationSession) -> None:
        from deephunter.core.types import BugClass

        priority_map = {
            BugClass.RCE: 10,
            BugClass.SQL_INJECTION: 9,
            BugClass.DESERIALIZATION: 8,
            BugClass.AUTH_BYPASS: 7,
            BugClass.SSRF: 7,
            BugClass.LFI: 6,
            BugClass.XSS: 5,
            BugClass.IDOR: 4,
        }

        for hyp in session.state.hypotheses:
            hyp_id = hyp["id"]
            try:
                session.update_hypothesis_confidence(hyp_id)
            except ValueError:
                continue
            bc_priority = max(
                (priority_map.get(BugClass(bc), 0) for bc in hyp.get("bug_classes", [])),
                default=0,
            )
            hyp["priority"] = bc_priority

        session.state.hypotheses.sort(key=lambda h: (h.get("priority", 0), h.get("confidence", 0)), reverse=True)


class ExperimentPlanningStage(ReasoningStage):
    """Stage 5: Plan experiments for high-priority hypotheses.

    Creates placeholder experiments for hypotheses that have
    confidence above the minimum threshold.
    """

    name = "experiment_planning"

    def process(self, session: InvestigationSession) -> None:
        for hyp in session.state.hypotheses:
            existing = [
                e for e in session.state.experiments
                if e.hypothesis_id == hyp["id"]
            ]
            if existing:
                continue

            if hyp.get("confidence", 0) >= 0.2:
                session.create_experiment(
                    hypothesis_id=hyp["id"],
                    description=f"Manual test for: {hyp['title']}",
                    procedure="Investigate the hypothesis manually",
                    expected_result="Vulnerability confirmed or refuted",
                )


class ResultRecordingStage(ReasoningStage):
    """Stage 6: Placeholder for recording experiment results.

    In future versions this will be populated by the CLI or AI.
    Currently creates a no-op placeholder.
    """

    name = "result_recording"

    def process(self, session: InvestigationSession) -> None:
        pass


class ConfidenceUpdateStage(ReasoningStage):
    """Stage 7: Recalculate confidence after results.

    Runs the confidence scorer across all hypotheses with completed
    experiments.
    """

    name = "confidence_update"

    def process(self, session: InvestigationSession) -> None:
        for hyp in session.state.hypotheses:
            hyp_id = hyp["id"]
            related_exps = [
                e for e in session.state.experiments
                if e.hypothesis_id == hyp_id
            ]
            if any(_status_in(e.status, "completed", "failed") for e in related_exps):
                try:
                    session.update_hypothesis_confidence(hyp_id, related_exps)
                except ValueError:
                    continue


class PivotGenerationStage(ReasoningStage):
    """Stage 8: Generate pivots from inconclusive or refuted hypotheses.

    When a hypothesis is refuted or inconclusive, a pivot is created
    to suggest the next direction.
    """

    name = "pivot_generation"

    def process(self, session: InvestigationSession) -> None:
        for exp in session.state.experiments:
            if exp.status.value in ("completed", "failed") and exp.actual_result:
                existing_pivots = [
                    p for p in session.state.pivots
                    if p.source_experiment_id == exp.id
                ]
                if existing_pivots:
                    continue

                session.create_pivot(
                    description=f"Review experiment {exp.id} results and adjust approach",
                    rationale="Experiment completed with actionable results",
                    reason="partial_confirmation",
                    source_experiment_id=exp.id,
                )


class FindingCreationStage(ReasoningStage):
    """Stage 9: Check for hypotheses that can be promoted to findings.

    Hypotheses with confidence >= 0.8 and at least one completed
    experiment are promoted to findings.
    """

    name = "finding_creation"

    def process(self, session: InvestigationSession) -> None:
        for hyp in session.state.hypotheses:
            if hyp.get("finding_id") is not None:
                continue
            if hyp.get("status") != "confirmed":
                continue

            related_exps = [
                e.id for e in session.state.experiments
                if e.hypothesis_id == hyp["id"]
                and _status_in(e.status, "completed")
                and e.actual_result.strip()
            ]
            if not related_exps:
                continue

            session.create_finding(
                title=hyp["title"],
                hypothesis_id=hyp["id"],
                description=hyp.get("description", ""),
                bug_classes=hyp.get("bug_classes", []),
                severity="medium",
                experiment_ids=related_exps,
            )


class ReportHookStage(ReasoningStage):
    """Stage 10: Hook for future report generation.

    Currently a no-op marker.  Future prompt builders will consume
    the investigation state here to generate structured reports.
    """

    name = "report_hook"

    def process(self, session: InvestigationSession) -> None:
        logger.info(
            "Investigation %s: %d observations, %d evidence, %d hypotheses, "
            "%d experiments, %d pivots, %d findings",
            session.investigation.id,
            len(session.state.observations),
            len(session.state.evidence),
            len(session.state.hypotheses),
            len(session.state.experiments),
            len(session.state.pivots),
            len(session.state.findings),
        )
