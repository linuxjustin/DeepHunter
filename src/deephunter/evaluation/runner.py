"""Benchmark runner — executes benchmarks and collects results."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkSuiteResult,
    DatasetType,
    EvaluationResult,
    Scorecard,
    SubsystemMetric,
)
from deephunter.evaluation.scoring import evaluate_entry
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)

EvaluationFunction = callable


@runtime_checkable
class EvaluationCallback(Protocol):
    """Protocol for running a benchmark entry against a system."""

    def __call__(self, entry: BenchmarkEntry) -> dict[str, Any]:
        ...

    def name(self) -> str:
        return "anonymous"


def _avg_metric(results: list[EvaluationResult], metric_name: str) -> float:
    values: list[float] = []
    for r in results:
        if r.metrics:
            val = getattr(r.metrics, metric_name, None)
            if val is not None and isinstance(val, SubsystemMetric):
                values.append(val.score)
    return sum(values) / len(values) if values else 0.0


def _traced_memory_peak() -> int:
    try:
        import tracemalloc

        tracemalloc.start()
        return 0
    except ImportError:
        return -1


def _stop_tracing() -> int:
    try:
        import tracemalloc

        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak
    except ImportError:
        return 0


class BenchmarkRunner:
    """Runs benchmark entries through a callback and aggregates results."""

    def __init__(self, callback: EvaluationCallback | None = None) -> None:
        self._callback = callback

    def with_callback(self, callback: EvaluationCallback) -> BenchmarkRunner:
        self._callback = callback
        return self

    def run_entry(self, entry: BenchmarkEntry, provider: str = "") -> EvaluationResult:
        callback = self._callback
        if callback is None:
            raise RuntimeError("No callback set. Call with_callback() first.")

        _traced_memory_peak()
        start = time.perf_counter()

        try:
            output = callback(entry)
        except Exception as exc:
            duration = (time.perf_counter() - start) * 1000.0
            peak = _stop_tracing()
            return EvaluationResult(
                entry_id=entry.id,
                entry_name=entry.name,
                duration_ms=duration,
                memory_usage_bytes=peak,
                provider=provider,
                passed=False,
                errors=[str(exc)],
            )

        duration = (time.perf_counter() - start) * 1000.0
        peak = _stop_tracing()

        result = evaluate_entry(
            entry=entry,
            actual_planner_steps=output.get("planner_steps", []),
            actual_technologies=output.get("technologies", []),
            actual_frameworks=output.get("frameworks", []),
            actual_attack_surface=output.get("attack_surface", []),
            actual_knowledge_packs=output.get("knowledge_packs", []),
            actual_reasoning=output.get("reasoning", []),
            duration_ms=duration,
            memory_bytes=peak,
            provider=provider,
        )
        result.duration_ms = duration
        result.memory_usage_bytes = peak
        return result

    def run_dataset(
        self, dataset: BenchmarkDataset, provider: str = ""
    ) -> BenchmarkSuiteResult:
        results: list[EvaluationResult] = []
        passed = 0
        failed = 0

        start = time.perf_counter()

        for entry in dataset.entries:
            er = self.run_entry(entry, provider=provider)
            results.append(er)
            if er.passed:
                passed += 1
            else:
                failed += 1

        duration = (time.perf_counter() - start) * 1000.0
        total = len(results)
        overall = (
            sum(r.metrics.overall_score() for r in results) / total
            if total > 0
            else 0.0
        )

        return BenchmarkSuiteResult(
            suite_name=dataset.name,
            dataset_id=dataset.id,
            dataset_type=(
                dataset.dataset_type.value
                if isinstance(dataset.dataset_type, DatasetType)
                else str(dataset.dataset_type)
            ),
            total_entries=total,
            passed=passed,
            failed=failed,
            overall_score=round(overall, 4),
            results=results,
            started_at=datetime.now(UTC).isoformat(),
            duration_ms=duration,
            provider=provider,
        )

    def run_filtered(
        self,
        dataset: BenchmarkDataset,
        *,
        tags: list[str] | None = None,
        difficulty: str | None = None,
        bug_class: str | None = None,
    ) -> BenchmarkSuiteResult:
        filtered = list(dataset.entries)

        if tags:
            tag_set = set(tags)
            filtered = [e for e in filtered if tag_set & set(e.tags)]

        if difficulty:
            filtered = [e for e in filtered if e.difficulty == difficulty]

        if bug_class:
            filtered = [e for e in filtered if bug_class in e.input.bug_classes]

        subset = BenchmarkDataset(
            name=f"{dataset.name} (filtered)",
            dataset_type=dataset.dataset_type,
            entries=filtered,
        )
        return self.run_dataset(subset)

    def run_regression(
        self,
        dataset: BenchmarkDataset,
        baseline: BenchmarkSuiteResult | None = None,
    ) -> tuple[BenchmarkSuiteResult, dict[str, Any]]:
        result = self.run_dataset(dataset)

        regressed = False
        score_delta = 0.0
        new_failures: list[str] = []
        fixed_tests: list[str] = []
        metric_deltas: dict[str, float] = {}

        if baseline is not None and baseline.results:
            prev_by_id = {r.entry_id: r for r in baseline.results}
            curr_by_id = {r.entry_id: r for r in result.results}

            for eid, curr in curr_by_id.items():
                prev = prev_by_id.get(eid)
                if prev is None:
                    continue
                if prev.passed and not curr.passed:
                    new_failures.append(curr.entry_name or eid)
                    regressed = True
                elif not prev.passed and curr.passed:
                    fixed_tests.append(curr.entry_name or eid)

            score_delta = round(result.overall_score - baseline.overall_score, 4)

            for mn in (
                "planner_accuracy",
                "reasoning_quality",
                "technology_accuracy",
                "methodology_coverage",
            ):
                pv = _avg_metric(baseline.results, mn)
                cv = _avg_metric(result.results, mn)
                metric_deltas[mn] = round(cv - pv, 4)

        regression_info: dict[str, Any] = {
            "regressed": regressed or bool(new_failures),
            "score_delta": score_delta,
            "new_failures": new_failures,
            "fixed_tests": fixed_tests,
            "metric_deltas": metric_deltas,
        }

        return result, regression_info

    def to_scorecard(self, result: BenchmarkSuiteResult) -> Scorecard:
        category_scores: dict[str, float] = {}
        threshold_compliance: dict[str, bool] = {}

        for er in result.results:
            if not er.metrics:
                continue
            for name, metric in er.metrics.__dict__.items():
                if not isinstance(metric, SubsystemMetric):
                    continue
                category_scores.setdefault(name, 0.0)
                category_scores[name] += metric.score
                if name not in threshold_compliance:
                    threshold_compliance[name] = True
                if not metric.passed:
                    threshold_compliance[name] = False

        total = len(result.results) or 1
        category_scores = {
            k: round(v / total, 4) for k, v in category_scores.items()
        }

        return Scorecard(
            name=result.suite_name,
            overall_score=result.overall_score,
            pass_rate=result.pass_rate(),
            category_scores=category_scores,
            threshold_compliance=threshold_compliance,
            total_tests=result.total_entries,
            passed=result.passed,
            failed=result.failed,
            duration_ms=result.duration_ms,
            metadata=result.metadata,
        )
