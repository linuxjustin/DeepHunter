"""Evaluation & Benchmark Framework for DeepHunter.

Measures quality across every subsystem:
  Planner · Methodology · Tech Intel · Framework Intel ·
  Knowledge Packs · Reasoning · Context · Prompt · Model Router · Agents

Provides dataset management, scoring, reporting, and CI integration.
"""

from deephunter.evaluation.metrics import EvaluationReport, Evaluator

from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkInput,
    BenchmarkSuiteResult,
    CIComparison,
    CICheckResult,
    DatasetType,
    EvaluationMetrics,
    EvaluationResult,
    ExpectedOutput,
    ExpectedReasoning,
    ExpectedStep,
    Leaderboard,
    LeaderboardCategory,
    LeaderboardEntry,
    RegressionReport,
    Scorecard,
    TrendPoint,
    TrendReport,
    SubsystemMetric,
)
from deephunter.evaluation.scoring import compute_metrics, evaluate_entry
from deephunter.evaluation.runner import BenchmarkRunner, EvaluationCallback
from deephunter.evaluation.reporter import (
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    ReportWriter,
)
from deephunter.evaluation.leaderboard import LeaderboardGenerator
from deephunter.evaluation.ci import CIIntegration
from deephunter.evaluation.providers import AIProvider, ProviderComparison, ProviderConfig, ProviderEvaluator, ProviderResult

from deephunter.evaluation.datasets import (
    GOLDEN_DATASET_SQLI_XSS,
    GOLDEN_DATASET_AUTH,
    GOLDEN_DATASET_SSRF,
    GOLDEN_DATASET_LARAVEL,
    GOLDEN_DATASET_CLOUD,
    REGRESSION_DATASET_PLANNER,
    REGRESSION_DATASET_METHODOLOGY,
    REGRESSION_DATASET_TECH_INTEL,
)

__all__ = [
    "AIProvider",
    "BenchmarkDataset",
    "BenchmarkEntry",
    "BenchmarkInput",
    "BenchmarkRunner",
    "BenchmarkSuiteResult",
    "CIComparison",
    "CICheckResult",
    "CIIntegration",
    "CSVReporter",
    "DatasetType",
    "EvaluationCallback",
    "EvaluationMetrics",
    "EvaluationReport",
    "EvaluationResult",
    "Evaluator",
    "ExpectedOutput",
    "ExpectedReasoning",
    "ExpectedStep",
    "GOLDEN_DATASET_AUTH",
    "GOLDEN_DATASET_CLOUD",
    "GOLDEN_DATASET_LARAVEL",
    "GOLDEN_DATASET_SQLI_XSS",
    "GOLDEN_DATASET_SSRF",
    "HTMLReporter",
    "JSONReporter",
    "Leaderboard",
    "LeaderboardCategory",
    "LeaderboardEntry",
    "LeaderboardGenerator",
    "MarkdownReporter",
    "ProviderComparison",
    "ProviderConfig",
    "ProviderEvaluator",
    "ProviderResult",
    "REGRESSION_DATASET_METHODOLOGY",
    "REGRESSION_DATASET_PLANNER",
    "REGRESSION_DATASET_TECH_INTEL",
    "RegressionReport",
    "ReportWriter",
    "Scorecard",
    "SubsystemMetric",
    "TrendPoint",
    "TrendReport",
    "compute_metrics",
    "evaluate_entry",
]
