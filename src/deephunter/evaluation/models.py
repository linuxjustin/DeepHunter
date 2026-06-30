"""Data models for the DeepHunter Evaluation & Benchmark Framework.

Covers the full evaluation pipeline:
  Dataset → Ground Truth → Metrics → Results → Reports → Leaderboard
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


# =============================================================================
# Dataset Types
# =============================================================================


class DatasetType(str, Enum):
    GOLDEN = "golden"
    REGRESSION = "regression"
    SYNTHETIC = "synthetic"
    MANUAL_REVIEW = "manual_review"
    REPLAY = "replay"
    CTF = "ctf"
    OWASP_JUICE_SHOP = "owasp_juice_shop"
    PORSTWIGGER_LABS = "portswigger_labs"
    DVWA = "dvwa"
    MUTILLIDAE = "mutillidae"
    BUG_BOUNTY = "bug_bounty"


class BenchmarkInput(BaseModel):
    """Input for a single benchmark entry."""

    target_url: str = ""
    technologies: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    attack_surface_areas: list[str] = Field(default_factory=list)
    auth_mechanisms: list[str] = Field(default_factory=list)
    bug_classes: list[str] = Field(default_factory=list)
    observation_types: list[str] = Field(default_factory=list)
    cloud_providers: list[str] = Field(default_factory=list)
    description: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class ExpectedStep(BaseModel):
    """Expected output from a single subsystem component."""

    phase: str = ""
    title: str = ""
    description: str = ""
    technologies: list[str] = Field(default_factory=list)
    bug_classes: list[str] = Field(default_factory=list)
    priority_score: float = 0.0
    risk: dict[str, float] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class ExpectedMethodology(BaseModel):
    methodology_id: str = ""
    checklist_items: list[dict] = Field(default_factory=list)
    manual_tests: list[dict] = Field(default_factory=list)
    coverage_areas: list[str] = Field(default_factory=list)


class ExpectedReasoning(BaseModel):
    hypotheses: list[str] = Field(default_factory=list)
    conclusions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    reasoning_steps: list[str] = Field(default_factory=list)


class ExpectedOutput(BaseModel):
    """Ground truth expected output for a benchmark entry."""

    planner_steps: list[ExpectedStep] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    attack_surface: list[str] = Field(default_factory=list)
    methodologies: list[ExpectedMethodology] = Field(default_factory=list)
    checklists: list[str] = Field(default_factory=list)
    workflows: list[str] = Field(default_factory=list)
    reasoning: ExpectedReasoning = Field(default_factory=ExpectedReasoning)
    confidence: float = 1.0
    priorities: dict[str, float] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    knowledge_packs: list[str] = Field(default_factory=list)


class BenchmarkEntry(BaseModel):
    """A single benchmark case with input and expected output."""

    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    name: str = ""
    description: str = ""
    input: BenchmarkInput = Field(default_factory=BenchmarkInput)
    expected: ExpectedOutput = Field(default_factory=ExpectedOutput)
    tags: list[str] = Field(default_factory=list)
    difficulty: str = "medium"  # easy, medium, hard, expert
    cwe_ids: list[str] = Field(default_factory=list)
    bug_bounty_source: str = ""


class BenchmarkDataset(BaseModel):
    """A versioned collection of benchmark entries."""

    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    name: str = ""
    version: str = "1.0.0"
    dataset_type: DatasetType = DatasetType.GOLDEN
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    entries: list[BenchmarkEntry] = Field(default_factory=list)
    author: str = "DeepHunter Evaluation Engine"
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def entry_count(self) -> int:
        return len(self.entries)

    def by_tag(self, tag: str) -> list[BenchmarkEntry]:
        return [e for e in self.entries if tag in e.tags]

    def by_difficulty(self, difficulty: str) -> list[BenchmarkEntry]:
        return [e for e in self.entries if e.difficulty == difficulty]

    def by_bug_class(self, bug_class: str) -> list[BenchmarkEntry]:
        return [
            e for e in self.entries
            if bug_class in e.input.bug_classes
        ]


# =============================================================================
# Evaluation Results
# =============================================================================


class SubsystemMetric(BaseModel):
    """Score for a single subsystem component (0.0–1.0)."""

    name: str = ""
    score: float = 0.0
    weight: float = 1.0
    threshold: float = 0.0
    passed: bool = False
    details: dict[str, float] = Field(default_factory=dict)
    raw_values: list[float] = Field(default_factory=list)


class EvaluationMetrics(BaseModel):
    """Aggregated metrics across all subsystems for one benchmark run."""

    planner_accuracy: SubsystemMetric = Field(default_factory=SubsystemMetric)
    technology_accuracy: SubsystemMetric = Field(default_factory=SubsystemMetric)
    framework_accuracy: SubsystemMetric = Field(default_factory=SubsystemMetric)
    methodology_coverage: SubsystemMetric = Field(default_factory=SubsystemMetric)
    checklist_coverage: SubsystemMetric = Field(default_factory=SubsystemMetric)
    reasoning_quality: SubsystemMetric = Field(default_factory=SubsystemMetric)
    context_quality: SubsystemMetric = Field(default_factory=SubsystemMetric)
    prompt_quality: SubsystemMetric = Field(default_factory=SubsystemMetric)
    knowledge_pack_coverage: SubsystemMetric = Field(default_factory=SubsystemMetric)
    attack_surface_coverage: SubsystemMetric = Field(default_factory=SubsystemMetric)
    relationship_accuracy: SubsystemMetric = Field(default_factory=SubsystemMetric)
    latency_ms: SubsystemMetric = Field(default_factory=SubsystemMetric)
    memory_bytes: SubsystemMetric = Field(default_factory=SubsystemMetric)
    throughput_eps: SubsystemMetric = Field(default_factory=SubsystemMetric)

    def overall_score(self) -> float:
        weighted_sum = 0.0
        total_weight = 0.0
        for metric in self.__dict__.values():
            if isinstance(metric, SubsystemMetric) and metric.weight > 0:
                weighted_sum += metric.score * metric.weight
                total_weight += metric.weight
        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def all_passed(self) -> bool:
        return all(
            metric.passed
            for metric in self.__dict__.values()
            if isinstance(metric, SubsystemMetric)
        )

    def failed_metrics(self) -> list[str]:
        return [
            metric.name
            for metric in self.__dict__.values()
            if isinstance(metric, SubsystemMetric) and not metric.passed
        ]


class EvaluationResult(BaseModel):
    """Result of evaluating a single benchmark entry."""

    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    dataset_id: str = ""
    entry_id: str = ""
    entry_name: str = ""
    metrics: EvaluationMetrics = Field(default_factory=EvaluationMetrics)
    duration_ms: float = 0.0
    memory_usage_bytes: int = 0
    actual_output: dict[str, list] = Field(default_factory=dict)
    provider: str = ""  # AI provider name if applicable
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    passed: bool = False
    errors: list[str] = Field(default_factory=list)


class BenchmarkSuiteResult(BaseModel):
    """Result of running an entire benchmark suite."""

    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    suite_name: str = ""
    dataset_id: str = ""
    dataset_type: str = ""
    total_entries: int = 0
    passed: int = 0
    failed: int = 0
    overall_score: float = 0.0
    results: list[EvaluationResult] = Field(default_factory=list)
    started_at: str = ""
    completed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    duration_ms: float = 0.0
    provider: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)

    def pass_rate(self) -> float:
        return self.passed / self.total_entries if self.total_entries > 0 else 0.0


# =============================================================================
# Scorecard & Reports
# =============================================================================


class Scorecard(BaseModel):
    """Compact evaluation scorecard for a benchmark run."""

    name: str = ""
    overall_score: float = 0.0
    pass_rate: float = 0.0
    category_scores: dict[str, float] = Field(default_factory=dict)
    threshold_compliance: dict[str, bool] = Field(default_factory=dict)
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    duration_ms: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, str] = Field(default_factory=dict)


class TrendPoint(BaseModel):
    """A single data point in a trend report."""

    timestamp: str = ""
    overall_score: float = 0.0
    pass_rate: float = 0.0
    total_tests: int = 0
    metrics: dict[str, float] = Field(default_factory=dict)


class TrendReport(BaseModel):
    """Historical comparison of scores over time."""

    name: str = ""
    points: list[TrendPoint] = Field(default_factory=list)
    current: TrendPoint = Field(default_factory=TrendPoint)
    previous: TrendPoint = Field(default_factory=TrendPoint)
    score_delta: float = 0.0
    pass_rate_delta: float = 0.0
    regression_detected: bool = False
    regressed_metrics: list[str] = Field(default_factory=list)


class RegressionReport(BaseModel):
    """Before/after comparison for regression detection."""

    suite_name: str = ""
    previous_score: float = 0.0
    current_score: float = 0.0
    score_delta: float = 0.0
    previous_pass_rate: float = 0.0
    current_pass_rate: float = 0.0
    pass_rate_delta: float = 0.0
    regressed: bool = False
    new_failures: list[str] = Field(default_factory=list)
    fixed_tests: list[str] = Field(default_factory=list)
    metric_deltas: dict[str, float] = Field(default_factory=dict)


# =============================================================================
# Leaderboard
# =============================================================================


class LeaderboardCategory(str, Enum):
    BEST_PLANNER = "best_planner"
    BEST_METHODOLOGY = "best_methodology"
    BEST_PROVIDER = "best_provider"
    BEST_RETRIEVAL = "best_retrieval"
    BEST_PROMPT = "best_prompt"
    BEST_REASONING = "best_reasoning"
    BEST_KNOWLEDGE_PACK = "best_knowledge_pack"
    BEST_OVERALL = "best_overall"


class LeaderboardEntry(BaseModel):
    """A single entry on a leaderboard."""

    rank: int = 0
    name: str = ""
    score: float = 0.0
    category: LeaderboardCategory = LeaderboardCategory.BEST_OVERALL
    entries_evaluated: int = 0
    pass_rate: float = 0.0
    avg_latency_ms: float = 0.0
    provider: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, str] = Field(default_factory=dict)


class Leaderboard(BaseModel):
    """A complete leaderboard ranking entries by score."""

    name: str = ""
    category: LeaderboardCategory = LeaderboardCategory.BEST_OVERALL
    entries: list[LeaderboardEntry] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    total_ranked: int = 0

    def top_n(self, n: int) -> list[LeaderboardEntry]:
        return sorted(self.entries, key=lambda e: -e.score)[:n]


# =============================================================================
# CI Integration
# =============================================================================


class CICheckResult(BaseModel):
    """Result of a CI quality gate check."""

    passed: bool = False
    score: float = 0.0
    threshold: float = 0.0
    regressions_detected: int = 0
    metrics_deltas: dict[str, float] = Field(default_factory=dict)
    summary: str = ""
    details_url: str = ""
    report_path: str = ""


class CIComparison(BaseModel):
    """Comparison with previous CI run for regression detection."""

    previous_run_id: str = ""
    current_run_id: str = ""
    previous_score: float = 0.0
    current_score: float = 0.0
    score_change: float = 0.0
    regressions: list[str] = Field(default_factory=list)
    improvements: list[str] = Field(default_factory=list)
    passed_quality_gate: bool = False
