"""AI provider evaluation — compares providers on accuracy, latency, cost."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from deephunter.evaluation.leaderboard import LeaderboardGenerator
from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkSuiteResult,
    Leaderboard,
    LeaderboardCategory,
)
from deephunter.evaluation.runner import BenchmarkRunner, EvaluationCallback


class AIProvider(StrEnum):
    CLAUDE = "claude"
    DEEPSEEK = "deepseek"
    QWEN = "qwen"
    GEMINI = "gemini"
    OPENAI = "openai"
    OLLAMA = "ollama"
    LOCAL = "local"


class ProviderConfig(BaseModel):
    provider: AIProvider = AIProvider.LOCAL
    model: str = ""
    api_key_env: str = ""
    endpoint: str = ""
    max_tokens: int = 4096
    temperature: float = 0.0
    timeout_seconds: int = 60
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0


class ProviderResult(BaseModel):
    provider: AIProvider
    model: str = ""
    suite_result: BenchmarkSuiteResult = Field(default_factory=BenchmarkSuiteResult)
    total_cost: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    avg_latency_ms: float = 0.0
    errors: int = 0


class ProviderComparison(BaseModel):
    comparisons: list[ProviderResult] = Field(default_factory=list)
    best_overall: str = ""
    best_accuracy: str = ""
    best_latency: str = ""
    best_cost: str = ""


class ProviderEvaluator:
    """Evaluates AI providers against benchmark datasets."""

    def __init__(self, callback: EvaluationCallback | None = None) -> None:
        self._callback = callback

    def evaluate_provider(
        self, dataset: BenchmarkDataset, config: ProviderConfig
    ) -> ProviderResult:
        if self._callback is None:
            raise RuntimeError("No callback configured. Set callback before evaluation.")

        total_input_tokens = 0
        total_output_tokens = 0
        error_count = 0
        latencies: list[float] = []

        cb = self._callback
        assert cb is not None

        class _TrackingWrapper:
            def __call__(self, entry: BenchmarkEntry) -> dict[str, Any]:
                nonlocal total_input_tokens, total_output_tokens, error_count
                result = cb(entry)
                total_input_tokens += result.get("input_tokens", 0)
                total_output_tokens += result.get("output_tokens", 0)
                if result.get("error"):
                    error_count += 1
                if "latency_ms" in result:
                    latencies.append(result["latency_ms"])
                return result  # type: ignore[no-any-return]

            @staticmethod
            def name() -> str:
                orig = getattr(cb, "name", lambda: "callback")
                return f"tracking_{orig()}"

        tracking_callback: EvaluationCallback = _TrackingWrapper()

        runner = BenchmarkRunner(callback=tracking_callback)
        suite_result = runner.run_dataset(
            dataset, provider=config.provider.value
        )

        total_cost = (
            (total_input_tokens / 1000.0) * config.cost_per_1k_input
            + (total_output_tokens / 1000.0) * config.cost_per_1k_output
        )

        n = max(suite_result.total_entries, 1)
        avg_latency = (
            sum(latencies) / len(latencies) if latencies else suite_result.duration_ms / n
        )

        return ProviderResult(
            provider=config.provider,
            model=config.model,
            suite_result=suite_result,
            total_cost=round(total_cost, 6),
            total_input_tokens=total_input_tokens,
            total_output_tokens=total_output_tokens,
            avg_latency_ms=round(avg_latency, 2),
            errors=error_count,
        )

    def compare_providers(
        self,
        dataset: BenchmarkDataset,
        configs: list[ProviderConfig],
    ) -> ProviderComparison:
        results: list[ProviderResult] = []
        for cfg in configs:
            result = self.evaluate_provider(dataset, cfg)
            results.append(result)

        best_overall = ""
        best_accuracy = ""
        best_latency = ""
        best_cost = ""
        best_overall_score = -1.0
        best_accuracy_score = -1.0
        best_latency_val = float("inf")
        best_cost_val = float("inf")

        for r in results:
            score = r.suite_result.overall_score
            if score > best_overall_score:
                best_overall_score = score
                best_overall = f"{r.provider.value}/{r.model}"

            if score > best_accuracy_score:
                best_accuracy_score = score
                best_accuracy = f"{r.provider.value}/{r.model}"

            if r.avg_latency_ms < best_latency_val:
                best_latency_val = r.avg_latency_ms
                best_latency = f"{r.provider.value}/{r.model}"

            if r.total_cost < best_cost_val:
                best_cost_val = r.total_cost
                best_cost = f"{r.provider.value}/{r.model}"

        return ProviderComparison(
            comparisons=results,
            best_overall=best_overall,
            best_accuracy=best_accuracy,
            best_latency=best_latency,
            best_cost=best_cost,
        )

    def generate_leaderboard(
        self, comparison: ProviderComparison
    ) -> dict[LeaderboardCategory, Leaderboard]:
        suite_results = [r.suite_result for r in comparison.comparisons]
        generator = LeaderboardGenerator()
        result: dict[LeaderboardCategory, Leaderboard] = generator.generate_all_categories(suite_results)
        return result
