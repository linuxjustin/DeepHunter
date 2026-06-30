"""Prompt Builder interface — typed context for future Prompt Builders.

This module defines the structured output contract that the reasoning
engine exposes to future Prompt Builder implementations.

DO NOT implement prompt generation here.
Only define the interface and data contracts.

Future Prompt Builders will consume these structured contexts
to generate prompts for any LLM provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deephunter.reasoning.models import (
    Evidence,
    Experiment,
    Finding,
    Investigation,
    Observation,
    Pivot,
)


@dataclass
class HypothesisContext:
    """Structured context about a single hypothesis for prompt building."""

    hypothesis_id: str = ""
    title: str = ""
    description: str = ""
    bug_classes: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    confidence: float = 0.0
    status: str = ""
    observations: list[Observation] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    experiments: list[Experiment] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class PromptBuilderContext:
    """Complete structured context for prompt generation.

    A Prompt Builder receives this context and generates
    model-specific prompts from it.
    """

    investigation: Investigation | None = None
    hypotheses: list[HypothesisContext] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    experiments: list[Experiment] = field(default_factory=list)
    pivots: list[Pivot] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    target: str = ""
    summary: str = ""


class PromptBuilderContextBuilder:
    """Builds a ``PromptBuilderContext`` from an investigation session.

    Usage::

        context = PromptBuilderContextBuilder.build(session)
        # Future: prompt_builder = LLMPromptBuilder(context).build()
    """

    @staticmethod
    def build(session: Any) -> PromptBuilderContext:
        """Build a structured context from an investigation session.

        Args:
            session: An ``InvestigationSession`` instance.

        Returns:
            A ``PromptBuilderContext`` ready for prompt generation.
        """
        inv: Investigation = session.investigation
        state = inv.state

        hyp_contexts: list[HypothesisContext] = []
        for hyp in state.hypotheses:
            hyp_observations = [
                o for o in state.observations
                if o.id in hyp.observation_ids
            ]
            hyp_evidence = [
                e for e in state.evidence
                if e.id in hyp.evidence_ids
            ]
            hyp_experiments = [
                e for e in state.experiments
                if e.id in hyp.experiment_ids
            ]
            hyp_findings = [
                f for f in state.findings
                if f.hypothesis_id == hyp.id
            ]

            hyp_contexts.append(
                HypothesisContext(
                    hypothesis_id=hyp.id,
                    title=hyp.title,
                    description=hyp.description,
                    bug_classes=[bc.value for bc in hyp.bug_classes],
                    technologies=hyp.technologies,
                    confidence=hyp.confidence,
                    status=hyp.status.value,
                    observations=hyp_observations,
                    evidence=hyp_evidence,
                    experiments=hyp_experiments,
                    findings=hyp_findings,
                )
            )

        summary_parts: list[str] = []
        if state.findings:
            summary_parts.append(f"{len(state.findings)} finding(s)")
        if state.hypotheses:
            summary_parts.append(f"{len(state.hypotheses)} hypothesis(es)")
        if state.observations:
            summary_parts.append(f"{len(state.observations)} observation(s)")
        if state.experiments:
            summary_parts.append(f"{len(state.experiments)} experiment(s)")

        return PromptBuilderContext(
            investigation=inv,
            hypotheses=hyp_contexts,
            observations=state.observations,
            evidence=state.evidence,
            experiments=state.experiments,
            pivots=state.pivots,
            findings=state.findings,
            target=inv.target,
            summary=", ".join(summary_parts) if summary_parts else "No data yet",
        )
