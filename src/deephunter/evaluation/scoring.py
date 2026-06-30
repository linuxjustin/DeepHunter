"""Scoring engine for benchmark evaluation.

Computes subsystem-level metrics and aggregate scores by comparing
actual outputs against ground truth expectations.
"""

from __future__ import annotations

from deephunter.evaluation.models import (
    BenchmarkEntry,
    BenchmarkInput,
    EvaluationMetrics,
    EvaluationResult,
    ExpectedOutput,
    ExpectedStep,
    SubsystemMetric,
)


def compute_metrics(
    entry: BenchmarkEntry,
    actual_planner_steps: list[dict],
    actual_technologies: list[str],
    actual_frameworks: list[str],
    actual_attack_surface: list[str],
    actual_knowledge_packs: list[str],
    actual_reasoning: list[str],
    duration_ms: float = 0.0,
    memory_bytes: int = 0,
) -> EvaluationMetrics:
    """Compute all subsystem metrics against ground truth."""
    expected = entry.expected

    planner = _compute_planner_accuracy(expected.planner_steps, actual_planner_steps)
    tech = _compute_tech_accuracy(expected.technologies, actual_technologies)
    fw = _compute_framework_accuracy(expected.frameworks, actual_frameworks)
    meth = _compute_methodology_coverage(expected, actual_planner_steps)
    checklist = _compute_checklist_coverage(expected.checklists, actual_planner_steps)
    reason = _compute_reasoning_quality(expected.reasoning.hypotheses, actual_reasoning)
    kp = _compute_knowledge_pack_coverage(expected.knowledge_packs, actual_knowledge_packs)
    as_coverage = _compute_attack_surface_coverage(expected.attack_surface, actual_attack_surface)
    rel = _compute_relationship_accuracy(expected, actual_knowledge_packs)

    return EvaluationMetrics(
        planner_accuracy=planner,
        technology_accuracy=tech,
        framework_accuracy=fw,
        methodology_coverage=meth,
        checklist_coverage=checklist,
        reasoning_quality=reason,
        context_quality=_make_metric("context_quality", 1.0 if tech.score > 0.5 else 0.0, weight=0.5),
        prompt_quality=_make_metric("prompt_quality", 1.0 if planner.score > 0.5 else 0.0, weight=0.3),
        knowledge_pack_coverage=kp,
        attack_surface_coverage=as_coverage,
        relationship_accuracy=rel,
        latency_ms=_make_metric("latency_ms", max(0.0, 1.0 - duration_ms / 10000.0), weight=0.2, threshold=0.5),
        memory_bytes=_make_metric("memory_bytes", max(0.0, 1.0 - memory_bytes / 500_000_000), weight=0.1),
        throughput_eps=_make_metric("throughput_eps", min(1.0, 1000.0 / max(duration_ms, 1)), weight=0.1),
    )


def _make_metric(
    name: str, score: float, weight: float = 1.0, threshold: float = 0.0
) -> SubsystemMetric:
    return SubsystemMetric(
        name=name,
        score=round(score, 4),
        weight=weight,
        threshold=threshold,
        passed=score >= threshold if threshold > 0 else True,
    )


def _jaccard(expected: list[str], actual: list[str]) -> float:
    set_e, set_a = set(expected), set(actual)
    if not set_e and not set_a:
        return 1.0
    if not set_e or not set_a:
        return 0.0
    return len(set_e & set_a) / len(set_e | set_a)


def _precision(expected: list[str], actual: list[str]) -> float:
    set_e, set_a = set(expected), set(actual)
    if not set_a:
        return 0.0
    if not set_e:
        return 1.0
    return len(set_e & set_a) / len(set_a)


def _recall(expected: list[str], actual: list[str]) -> float:
    set_e, set_a = set(expected), set(actual)
    if not set_e:
        return 1.0
    return len(set_e & set_a) / len(set_e)


def _f1(prec: float, rec: float) -> float:
    return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0


def _compute_planner_accuracy(
    expected: list[ExpectedStep], actual: list[dict]
) -> SubsystemMetric:
    if not expected:
        return _make_metric("planner_accuracy", 1.0, weight=1.0, threshold=0.5)

    actual_titles = [s.get("title", "") for s in actual]
    expected_titles = [s.title for s in expected]

    prec = _precision(expected_titles, actual_titles)
    rec = _recall(expected_titles, actual_titles)
    score = _f1(prec, rec)

    return SubsystemMetric(
        name="planner_accuracy",
        score=round(score, 4),
        weight=1.0,
        threshold=0.5,
        passed=score >= 0.5,
        details={"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(score, 4)},
        raw_values=[score],
    )


def _compute_tech_accuracy(
    expected: list[str], actual: list[str]
) -> SubsystemMetric:
    score = _jaccard(expected, actual)
    prec = _precision(expected, actual)
    rec = _recall(expected, actual)
    return SubsystemMetric(
        name="technology_accuracy",
        score=round(score, 4),
        weight=0.8,
        threshold=0.3,
        passed=score >= 0.3,
        details={"precision": round(prec, 4), "recall": round(rec, 4), "jaccard": round(score, 4)},
        raw_values=[score],
    )


def _compute_framework_accuracy(
    expected: list[str], actual: list[str]
) -> SubsystemMetric:
    score = _jaccard(expected, actual)
    return _make_metric("framework_accuracy", score, weight=0.7, threshold=0.3)


def _compute_methodology_coverage(
    expected: ExpectedOutput, actual_steps: list[dict]
) -> SubsystemMetric:
    if not expected.methodologies:
        return _make_metric("methodology_coverage", 1.0, weight=0.6)

    expected_areas: set[str] = set()
    for m in expected.methodologies:
        expected_areas.update(m.coverage_areas)

    actual_titles = {s.get("title", "") for s in actual_steps}
    covered = expected_areas & actual_titles
    score = len(covered) / len(expected_areas) if expected_areas else 1.0

    return SubsystemMetric(
        name="methodology_coverage",
        score=round(score, 4),
        weight=0.6,
        threshold=0.4,
        passed=score >= 0.4,
        details={"covered": len(covered), "expected": len(expected_areas)},
        raw_values=[score],
    )


def _compute_checklist_coverage(
    expected_checklists: list[str], actual_steps: list[dict]
) -> SubsystemMetric:
    if not expected_checklists:
        return _make_metric("checklist_coverage", 1.0, weight=0.5)

    actual_titles = {s.get("title", "").lower() for s in actual_steps}
    matched = sum(
        1 for cl in expected_checklists if cl.lower() in " ".join(actual_titles)
    )
    score = matched / len(expected_checklists)

    return SubsystemMetric(
        name="checklist_coverage",
        score=round(score, 4),
        weight=0.5,
        threshold=0.3,
        passed=score >= 0.3,
        details={"matched": matched, "total": len(expected_checklists)},
        raw_values=[score],
    )


def _compute_reasoning_quality(
    expected_hypotheses: list[str], actual_reasoning: list[str]
) -> SubsystemMetric:
    score = _jaccard(expected_hypotheses, actual_reasoning)
    return _make_metric("reasoning_quality", score, weight=0.9, threshold=0.3)


def _compute_knowledge_pack_coverage(
    expected_packs: list[str], actual_packs: list[str]
) -> SubsystemMetric:
    score = _jaccard(expected_packs, actual_packs)
    return _make_metric("knowledge_pack_coverage", score, weight=0.7, threshold=0.3)


def _compute_attack_surface_coverage(
    expected: list[str], actual: list[str]
) -> SubsystemMetric:
    score = _jaccard(expected, actual)
    return _make_metric("attack_surface_coverage", score, weight=0.6, threshold=0.3)


def _compute_relationship_accuracy(
    expected: ExpectedOutput, actual_kp: list[str]
) -> SubsystemMetric:
    score = _jaccard(expected.knowledge_packs, actual_kp)
    return _make_metric("relationship_accuracy", score, weight=0.4, threshold=0.2)


# =============================================================================
# High-level result builder
# =============================================================================


def evaluate_entry(
    entry: BenchmarkEntry,
    actual_planner_steps: list[dict],
    actual_technologies: list[str],
    actual_frameworks: list[str],
    actual_attack_surface: list[str],
    actual_knowledge_packs: list[str],
    actual_reasoning: list[str],
    duration_ms: float = 0.0,
    memory_bytes: int = 0,
    provider: str = "",
) -> EvaluationResult:
    """Evaluate a single benchmark entry and return a complete result."""
    metrics = compute_metrics(
        entry,
        actual_planner_steps,
        actual_technologies,
        actual_frameworks,
        actual_attack_surface,
        actual_knowledge_packs,
        actual_reasoning,
        duration_ms,
        memory_bytes,
    )
    return EvaluationResult(
        dataset_id="",
        entry_id=entry.id,
        entry_name=entry.name,
        metrics=metrics,
        duration_ms=duration_ms,
        memory_usage_bytes=memory_bytes,
        actual_output={
            "planner_steps": actual_planner_steps,
            "technologies": actual_technologies,
            "frameworks": actual_frameworks,
            "attack_surface": actual_attack_surface,
            "knowledge_packs": actual_knowledge_packs,
            "reasoning": actual_reasoning,
        },
        provider=provider,
        passed=metrics.all_passed(),
    )
