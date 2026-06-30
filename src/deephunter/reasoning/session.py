"""Investigation session management.

Manages the lifecycle of a single investigation, including
state persistence, graph management, and event emission.

A session wraps an ``Investigation``, a ``ReasoningGraph``,
and a ``ReasoningEventBus`` to provide the full investigation API.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from deephunter.core.exceptions import ReasoningError
from deephunter.reasoning.confidence import (
    ConfidenceScorer,
    HypothesisStatusScorer,
    WeightedEvidenceScorer,
)
from deephunter.reasoning.events import (
    ConfidenceChangedEvent,
    EvidenceAddedEvent,
    ExperimentCompletedEvent,
    ExperimentCreatedEvent,
    FindingCreatedEvent,
    HypothesisCreatedEvent,
    HypothesisStatusChangedEvent,
    HypothesisUpdatedEvent,
    ObservationCreatedEvent,
    PivotCreatedEvent,
    ReasoningEventBus,
)
from deephunter.reasoning.graph import EdgeType, ReasoningGraph
from deephunter.reasoning.models import (
    Evidence,
    Experiment,
    ExperimentStatus,
    Finding,
    FindingSeverity,
    Hypothesis,
    HypothesisStatus,
    Investigation,
    InvestigationState,
    Observation,
    Pivot,
    PivotReason,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class InvestigationSession:
    """Manages a single security investigation.

    Provides the public API for all reasoning operations:

    - Creating observations and adding evidence
    - Managing hypotheses and experiments
    - Tracking pivots and findings
    - Persisting and loading investigation state

    Usage::

        session = InvestigationSession.new("https://example.com")
        obs = session.create_observation(ObservationType.ENDPOINT, "Login page found")
        session.add_evidence(obs.id, "HTTP 200 OK on /login")
        session.run_pipeline()
    """

    def __init__(
        self,
        investigation: Investigation,
        graph: ReasoningGraph | None = None,
        event_bus: ReasoningEventBus | None = None,
        confidence_scorer: ConfidenceScorer | None = None,
    ) -> None:
        self._inv = investigation
        self._graph = graph or ReasoningGraph()
        self._event_bus = event_bus or ReasoningEventBus()
        self._scorer = confidence_scorer or WeightedEvidenceScorer()
        self._status_scorer = HypothesisStatusScorer()

    # ── Factory ───────────────────────────────────────────────────

    @classmethod
    def new(
        cls,
        target: str,
        name: str = "",
        sko_ids: list[str] | None = None,
    ) -> InvestigationSession:
        """Create a new investigation session.

        Args:
            target: The target being investigated.
            name: Optional human-readable name.
            sko_ids: Optional SKO IDs retrieved for this investigation.

        Returns:
            A new InvestigationSession ready for use.
        """
        inv = Investigation(
            name=name or f"Investigation: {target}",
            target=target,
            state=InvestigationState(target=target),
            sko_ids=sko_ids or [],
        )
        return cls(inv)

    # ── Properties ────────────────────────────────────────────────

    @property
    def investigation(self) -> Investigation:
        return self._inv

    @property
    def graph(self) -> ReasoningGraph:
        return self._graph

    @property
    def event_bus(self) -> ReasoningEventBus:
        return self._event_bus

    @property
    def events(self) -> ReasoningEventBus:
        return self._event_bus

    @property
    def state(self) -> InvestigationState:
        return self._inv.state

    # ── Observation management ────────────────────────────────────

    def create_observation(
        self,
        obs_type: str,
        description: str,
        detail: str = "",
        source: str = "",
        tags: list[str] | None = None,
    ) -> Observation:
        """Create and register a new observation.

        Args:
            obs_type: The ``ObservationType`` value string.
            description: Human-readable description.
            detail: Technical detail or observed payload.
            source: Where this was observed.
            tags: Optional tags.

        Returns:
            The created Observation.
        """
        from deephunter.reasoning.models import ObservationType as OT

        try:
            ot = OT(obs_type)
        except ValueError:
            ot = OT.OTHER

        obs = Observation(
            type=ot,
            description=description,
            detail=detail,
            source=source,
            tags=tags or [],
        )
        self.state.add_observation(obs)
        self._graph.add_node(obs)
        self._event_bus.emit(
            ObservationCreatedEvent(
                observation=obs, investigation_id=self._inv.id
            )
        )
        logger.debug("Created observation %s: %s", obs.id, description)
        return obs

    def add_evidence(
        self,
        observation_id: str,
        content: str,
        source: str = "",
        ev_type: str = "raw",
    ) -> Evidence:
        """Add evidence supporting an observation.

        Args:
            observation_id: The observation to support.
            content: The evidence data (response, code, etc.).
            source: Origin of the evidence.
            ev_type: ``EvidenceType`` value string.

        Returns:
            The created Evidence.

        Raises:
            ValueError: If the observation does not exist.
        """
        from deephunter.reasoning.models import EvidenceType as ET

        if not self._graph.has_node(observation_id):
            logger.warning("Observation not found: %s", observation_id)
            return None

        try:
            et = ET(ev_type)
        except ValueError:
            et = ET.RAW

        ev = Evidence(
            observation_id=observation_id,
            content=content,
            source=source,
            type=et,
        )
        self.state.add_evidence(ev)
        self._graph.add_node(ev)
        self._graph.add_edge(ev.id, observation_id, EdgeType.SUPPORTS)
        self._event_bus.emit(
            EvidenceAddedEvent(
                evidence=ev,
                observation_id=observation_id,
                investigation_id=self._inv.id,
            )
        )
        logger.debug("Added evidence %s for observation %s", ev.id, observation_id)
        return ev

    # ── Hypothesis management ─────────────────────────────────────

    def create_hypothesis(
        self,
        title: str,
        description: str = "",
        bug_classes: list[str] | None = None,
        technologies: list[str] | None = None,
        rationale: str = "",
        observation_ids: list[str] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> Hypothesis:
        """Create a hypothesis and wire it to supporting observations.

        Args:
            title: Hypothesis title.
            description: Detailed description.
            bug_classes: List of bug class strings.
            technologies: List of technology strings.
            rationale: Why this hypothesis is worth investigating.
            observation_ids: Observations that suggest this hypothesis.
            evidence_ids: Evidence supporting those observations.

        Returns:
            The created Hypothesis.
        """
        from deephunter.core.types import BugClass

        bc_list: list[BugClass] = []
        for bc_str in (bug_classes or []):
            try:
                bc_list.append(BugClass(bc_str))
            except ValueError:
                pass

        hyp = Hypothesis(
            title=title,
            description=description,
            bug_classes=bc_list,
            technologies=technologies or [],
            rationale=rationale,
            observation_ids=observation_ids or [],
            evidence_ids=evidence_ids or [],
        )
        self._inv.state.hypotheses.append(hyp)
        self._inv.updated_at = datetime.now(UTC)

        self._event_bus.emit(
            HypothesisCreatedEvent(
                hypothesis_title=title,
                bug_classes=bug_classes or [],
                investigation_id=self._inv.id,
            )
        )
        logger.debug("Created hypothesis: %s", title)
        return hyp

    def update_hypothesis_confidence(
        self, hypothesis_id: str, experiments: list[Experiment] | None = None
    ) -> float:
        """Recalculate and update a hypothesis confidence score.

        Args:
            hypothesis_id: The hypothesis to update.
            experiments: Optional list of experiments (defaults to state list).

        Returns:
            The new confidence score.

        Raises:
            ValueError: If the hypothesis is not found.
        """
        hyp = self._find_hypothesis(hypothesis_id)
        if hyp is None:
            raise ValueError(f"Hypothesis not found: {hypothesis_id}")

        old_conf = hyp.confidence

        obs = [
            o for o in self.state.observations
            if o.id in hyp.observation_ids
        ]
        ev = [
            e for e in self.state.evidence
            if e.id in hyp.evidence_ids
        ]
        exps = experiments or [
            e for e in self.state.experiments
            if e.id in hyp.experiment_ids
        ]

        new_conf = self._scorer.score(obs, ev, exps)
        hyp.confidence = new_conf
        hyp.updated_at = datetime.now(UTC)

        new_status = self._status_scorer.determine_status(new_conf, exps)
        old_status = hyp.status
        if new_status != old_status:
            hyp.status = new_status
            self._event_bus.emit(
                HypothesisStatusChangedEvent(
                    hypothesis_id=hypothesis_id,
                    old_status=old_status.value,
                    new_status=new_status.value,
                    investigation_id=self._inv.id,
                )
            )

        self._event_bus.emit(
            HypothesisUpdatedEvent(
                hypothesis_title=hyp.title,
                old_confidence=old_conf,
                new_confidence=new_conf,
                new_status=hyp.status.value,
                investigation_id=self._inv.id,
            )
        )

        if abs(new_conf - old_conf) > 0.15:
            self._event_bus.emit(
                ConfidenceChangedEvent(
                    hypothesis_id=hypothesis_id,
                    old_score=old_conf,
                    new_score=new_conf,
                    reason="evidence_or_experiment_update",
                    investigation_id=self._inv.id,
                )
            )

        logger.debug(
            "Updated hypothesis %s confidence: %.2f -> %.2f",
            hypothesis_id, old_conf, new_conf,
        )
        return new_conf

    # ── Experiment management ─────────────────────────────────────

    def create_experiment(
        self,
        hypothesis_id: str,
        description: str,
        procedure: str = "",
        expected_result: str = "",
    ) -> Experiment:
        """Plan a new experiment for a hypothesis.

        Args:
            hypothesis_id: The hypothesis to test.
            description: What this experiment does.
            procedure: Step-by-step instructions.
            expected_result: What should happen if vulnerable.

        Returns:
            The created Experiment.
        """
        if self._find_hypothesis(hypothesis_id) is None:
            logger.warning("Hypothesis not found: %s", hypothesis_id)
            return None

        exp = Experiment(
            hypothesis_id=hypothesis_id,
            description=description,
            procedure=procedure,
            expected_result=expected_result,
            status=ExperimentStatus.PLANNED,
        )
        self.state.experiments.append(exp)
        self._graph.add_node(exp)
        if self._graph.has_node(hypothesis_id):
            self._graph.add_edge(hypothesis_id, exp.id, EdgeType.TESTS)

        self._event_bus.emit(
            ExperimentCreatedEvent(
                experiment=exp, investigation_id=self._inv.id
            )
        )
        return exp

    def complete_experiment(
        self,
        experiment_id: str,
        actual_result: str,
        status: str = "completed",
    ) -> Experiment:
        """Record the result of a completed experiment.

        Updates experiment status, emits events, and recalculates
        hypothesis confidence.

        Args:
            experiment_id: The experiment to complete.
            actual_result: What actually happened.
            status: ``ExperimentStatus`` value.

        Returns:
            The updated Experiment.

        Raises:
            ValueError: If the experiment is not found.
        """
        exp = self._find_experiment(experiment_id)
        if exp is None:
            raise ValueError(f"Experiment not found: {experiment_id}")

        try:
            exp.status = ExperimentStatus(status)
        except ValueError:
            exp.status = ExperimentStatus.COMPLETED

        exp.actual_result = actual_result
        exp.completed_at = datetime.now(UTC)

        passed = exp.status == ExperimentStatus.COMPLETED and bool(actual_result.strip())

        self._event_bus.emit(
            ExperimentCompletedEvent(
                experiment=exp,
                passed=passed,
                investigation_id=self._inv.id,
            )
        )

        self.update_hypothesis_confidence(exp.hypothesis_id)

        logger.debug(
            "Completed experiment %s: %s (passed=%s)",
            experiment_id, actual_result[:50], passed,
        )
        return exp

    # ── Pivot management ──────────────────────────────────────────

    def create_pivot(
        self,
        description: str,
        rationale: str = "",
        reason: str = "other",
        source_experiment_id: str | None = None,
    ) -> Pivot:
        """Create a pivot to a new investigation direction.

        Args:
            description: What new direction to take.
            rationale: Why this pivot makes sense.
            reason: ``PivotReason`` value string.
            source_experiment_id: Optional experiment that triggered this.

        Returns:
            The created Pivot.
        """
        try:
            pr = PivotReason(reason)
        except ValueError:
            pr = PivotReason.OTHER

        pivot = Pivot(
            description=description,
            rationale=rationale,
            reason=pr,
            source_experiment_id=source_experiment_id,
        )
        self.state.pivots.append(pivot)
        self._graph.add_node(pivot)

        if source_experiment_id and self._graph.has_node(source_experiment_id):
            self._graph.add_edge(source_experiment_id, pivot.id, EdgeType.GENERATES)

        self._event_bus.emit(
            PivotCreatedEvent(pivot=pivot, investigation_id=self._inv.id)
        )
        return pivot

    # ── Finding management ────────────────────────────────────────

    def create_finding(
        self,
        title: str,
        hypothesis_id: str,
        description: str = "",
        bug_classes: list[str] | None = None,
        severity: str = "medium",
        cwe_ids: list[str] | None = None,
        experiment_ids: list[str] | None = None,
    ) -> Finding:
        """Create a finding from a confirmed hypothesis.

        Args:
            title: Finding title.
            hypothesis_id: The confirmed hypothesis.
            description: Detailed description.
            bug_classes: Bug class strings.
            severity: Severity value.
            cwe_ids: CWE identifier strings.
            experiment_ids: Experiments that confirmed this.

        Returns:
            The created Finding.

        Raises:
            ValueError: If the hypothesis is not found.
        """
        hyp = self._find_hypothesis(hypothesis_id)
        if hyp is None:
            raise ValueError(f"Hypothesis not found: {hypothesis_id}")

        try:
            sev = FindingSeverity(severity)
        except ValueError:
            sev = FindingSeverity.MEDIUM

        from deephunter.core.types import BugClass

        bc_list: list[BugClass] = []
        for bc_str in (bug_classes or []):
            try:
                bc_list.append(BugClass(bc_str))
            except ValueError:
                pass

        finding = Finding(
            title=title,
            description=description,
            bug_classes=bc_list,
            severity=sev,
            cwe_ids=cwe_ids or [],
            hypothesis_id=hypothesis_id,
            experiment_ids=experiment_ids or [],
            evidence_ids=hyp.evidence_ids,
        )
        self.state.findings.append(finding)
        self._graph.add_node(finding)
        if self._graph.has_node(hypothesis_id):
            self._graph.add_edge(hypothesis_id, finding.id, EdgeType.CONFIRMS)

        hyp.finding_id = finding.id
        hyp.status = HypothesisStatus.CONFIRMED

        self._event_bus.emit(
            FindingCreatedEvent(
                finding=finding, investigation_id=self._inv.id
            )
        )
        logger.debug("Created finding %s: %s", finding.id, title)
        return finding

    # ── Persistence ───────────────────────────────────────────────

    def save(self, path: str | Path) -> Path:
        """Persist the investigation (state + graph) to a JSON file.

        Args:
            path: Destination file path.

        Returns:
            The resolved Path.
        """
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "investigation": self._inv.model_dump_for_storage(),
            "graph": self._graph.to_dict(),
        }
        p.write_text(json.dumps(data, indent=2, default=str), "utf-8")
        logger.debug("Saved investigation %s to %s", self._inv.id, p)
        return p

    @classmethod
    def load(cls, path: str | Path) -> InvestigationSession:
        """Load an investigation from a JSON file.

        Args:
            path: Path to the saved investigation JSON.

        Returns:
            A restored InvestigationSession.

        Raises:
            FileNotFoundError: If the path does not exist.
            ReasoningError: If the file is corrupt.
        """
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Investigation file not found: {p}")
        try:
            data = json.loads(p.read_text("utf-8"))
            inv = Investigation.from_dict(data["investigation"])
            graph = ReasoningGraph.from_dict(data.get("graph", {"nodes": [], "edges": []}))
            return cls(inv, graph=graph)
        except (json.JSONDecodeError, KeyError, Exception) as exc:
            raise ReasoningError(f"Failed to load investigation from {p}: {exc}") from exc

    # ── Pipeline integration ──────────────────────────────────────

    def record_result(
        self,
        experiment_id: str,
        status: str,
        actual_result: str,
    ) -> bool:
        """Record experiment result (convenience wrapper).

        Args:
            experiment_id: The experiment to update.
            status: ExperimentStatus value.
            actual_result: What actually happened.

        Returns:
            True on success, False if the experiment was not found.
        """
        try:
            self.complete_experiment(experiment_id, actual_result, status)
            return True
        except ValueError:
            return False

    def get_summary(self) -> str:
        """Return a human-readable summary of the investigation state."""
        parts = []
        if self._inv.state.observations:
            parts.append(f"{len(self._inv.state.observations)} observations")
        if self._inv.state.hypotheses:
            parts.append(f"{len(self._inv.state.hypotheses)} hypotheses")
        if self._inv.state.experiments:
            parts.append(f"{len(self._inv.state.experiments)} experiments")
        if self._inv.state.pivots:
            parts.append(f"{len(self._inv.state.pivots)} pivots")
        if self._inv.state.findings:
            parts.append(f"{len(self._inv.state.findings)} findings")
        return ", ".join(parts) if parts else "No data yet"

    def receive_skos(self, sko_ids: list[str]) -> None:
        """Accept SKO IDs from the knowledge store.

        This is the integration point with the Knowledge Engine.
        Future: the pipeline will use these SKOs to seed observations.

        Args:
            sko_ids: IDs of SecurityKnowledgeObjects relevant to this investigation.
        """
        self._inv.sko_ids = list(set(self._inv.sko_ids + sko_ids))

    # ── Internal helpers ──────────────────────────────────────────

    def _find_hypothesis(self, hyp_id: str) -> Hypothesis | None:
        for hyp in self._inv.state.hypotheses:
            if hyp.id == hyp_id:
                return hyp
        return None

    def _find_experiment(self, exp_id: str) -> Experiment | None:
        for exp in self.state.experiments:
            if exp.id == exp_id:
                return exp
        return None
