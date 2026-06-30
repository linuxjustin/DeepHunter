"""Leaderboard generation — ranks entries by score across categories."""

from __future__ import annotations

from datetime import UTC, datetime

from deephunter.evaluation.models import (
    BenchmarkSuiteResult,
    Leaderboard,
    LeaderboardCategory,
    LeaderboardEntry,
    SubsystemMetric,
)


class LeaderboardGenerator:
    """Ranks benchmark suite results into leaderboards by category."""

    _METRIC_MAP: dict[LeaderboardCategory, str] = {
        LeaderboardCategory.BEST_PLANNER: "planner_accuracy",
        LeaderboardCategory.BEST_METHODOLOGY: "methodology_coverage",
        LeaderboardCategory.BEST_RETRIEVAL: "context_quality",
        LeaderboardCategory.BEST_PROMPT: "prompt_quality",
        LeaderboardCategory.BEST_REASONING: "reasoning_quality",
        LeaderboardCategory.BEST_KNOWLEDGE_PACK: "knowledge_pack_coverage",
    }

    def generate(
        self,
        results: list[BenchmarkSuiteResult],
        category: LeaderboardCategory = LeaderboardCategory.BEST_OVERALL,
    ) -> Leaderboard:
        if category == LeaderboardCategory.BEST_OVERALL:
            entries = self.rank_by_overall(results)
        elif category == LeaderboardCategory.BEST_PLANNER:
            entries = self.rank_by_planner(results)
        elif category == LeaderboardCategory.BEST_REASONING:
            entries = self.rank_by_reasoning(results)
        elif category == LeaderboardCategory.BEST_PROVIDER:
            entries = self.rank_by_provider(results)
        else:
            metric_name = self._METRIC_MAP.get(category, "overall_score")
            entries = self.rank_by_metric(results, metric_name)

        for i, e in enumerate(entries, 1):
            e.rank = i
            e.category = category

        return Leaderboard(
            name=f"Leaderboard: {category.value}",
            category=category,
            entries=entries,
            total_ranked=len(entries),
            generated_at=datetime.now(UTC).isoformat(),
        )

    def generate_all_categories(
        self, results: list[BenchmarkSuiteResult]
    ) -> dict[LeaderboardCategory, Leaderboard]:
        return {cat: self.generate(results, cat) for cat in LeaderboardCategory}

    @staticmethod
    def _build_entry(
        result: BenchmarkSuiteResult,
        score: float,
        category: LeaderboardCategory,
    ) -> LeaderboardEntry:
        return LeaderboardEntry(
            rank=0,
            name=result.suite_name or result.id,
            score=round(score, 4),
            category=category,
            entries_evaluated=result.total_entries,
            pass_rate=result.pass_rate(),
            avg_latency_ms=(
                result.duration_ms / max(result.total_entries, 1)
            ),
            provider=result.provider,
        )

    @staticmethod
    def _avg_subsystem(
        results: list[BenchmarkSuiteResult], metric_name: str
    ) -> dict[str, float]:
        """Return suite_name -> average of a subsystem metric across entries."""
        out: dict[str, float] = {}
        for r in results:
            scores = [
                getattr(er.metrics, metric_name, SubsystemMetric()).score
                for er in r.results
                if er.metrics
            ]
            avg = sum(scores) / len(scores) if scores else 0.0
            out[r.suite_name or r.id] = avg
        return out

    @staticmethod
    def rank_by_overall(
        results: list[BenchmarkSuiteResult],
    ) -> list[LeaderboardEntry]:
        entries = [
            LeaderboardGenerator._build_entry(r, r.overall_score, LeaderboardCategory.BEST_OVERALL)
            for r in results
        ]
        entries.sort(key=lambda e: -e.score)
        for i, e in enumerate(entries, 1):
            e.rank = i
        return entries

    @staticmethod
    def rank_by_planner(
        results: list[BenchmarkSuiteResult],
    ) -> list[LeaderboardEntry]:
        avgs = LeaderboardGenerator._avg_subsystem(results, "planner_accuracy")
        entries = [
            LeaderboardGenerator._build_entry(
                next(r for r in results if (r.suite_name or r.id) == name),
                score,
                LeaderboardCategory.BEST_PLANNER,
            )
            for name, score in avgs.items()
        ]
        entries.sort(key=lambda e: -e.score)
        for i, e in enumerate(entries, 1):
            e.rank = i
        return entries

    @staticmethod
    def rank_by_provider(
        results: list[BenchmarkSuiteResult],
    ) -> list[LeaderboardEntry]:
        grouped: dict[str, list[BenchmarkSuiteResult]] = {}
        for r in results:
            key = r.provider or "unknown"
            grouped.setdefault(key, []).append(r)

        entries: list[LeaderboardEntry] = []
        for provider, group in grouped.items():
            avg_score = sum(r.overall_score for r in group) / len(group)
            total_entries = sum(r.total_entries for r in group)
            total_passed = sum(r.passed for r in group)
            avg_latency = (
                sum(r.duration_ms for r in group) / max(total_entries, 1)
            )
            entries.append(
                LeaderboardEntry(
                    rank=0,
                    name=provider,
                    score=round(avg_score, 4),
                    category=LeaderboardCategory.BEST_PROVIDER,
                    entries_evaluated=total_entries,
                    pass_rate=(
                        total_passed / total_entries if total_entries > 0 else 0.0
                    ),
                    avg_latency_ms=avg_latency,
                    provider=provider,
                )
            )
        entries.sort(key=lambda e: -e.score)
        for i, e in enumerate(entries, 1):
            e.rank = i
        return entries

    @staticmethod
    def rank_by_reasoning(
        results: list[BenchmarkSuiteResult],
    ) -> list[LeaderboardEntry]:
        avgs = LeaderboardGenerator._avg_subsystem(results, "reasoning_quality")
        entries = [
            LeaderboardGenerator._build_entry(
                next(r for r in results if (r.suite_name or r.id) == name),
                score,
                LeaderboardCategory.BEST_REASONING,
            )
            for name, score in avgs.items()
        ]
        entries.sort(key=lambda e: -e.score)
        for i, e in enumerate(entries, 1):
            e.rank = i
        return entries

    @staticmethod
    def rank_by_metric(
        results: list[BenchmarkSuiteResult],
        metric_name: str,
    ) -> list[LeaderboardEntry]:
        avgs = LeaderboardGenerator._avg_subsystem(results, metric_name)
        entries = [
            LeaderboardGenerator._build_entry(
                next(r for r in results if (r.suite_name or r.id) == name),
                score,
                LeaderboardCategory.BEST_OVERALL,
            )
            for name, score in avgs.items()
        ]
        entries.sort(key=lambda e: -e.score)
        for i, e in enumerate(entries, 1):
            e.rank = i
        return entries
