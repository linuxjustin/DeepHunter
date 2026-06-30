"""Tests for the evaluation framework."""

from __future__ import annotations

import pytest

from deephunter.core.exceptions import EvaluationError
from deephunter.evaluation.metrics import EvaluationReport, Evaluator
from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkInput,
    BenchmarkSuiteResult,
    DatasetType,
    EvaluationMetrics,
    EvaluationResult,
    ExpectedOutput,
    ExpectedReasoning,
    ExpectedStep,
    Leaderboard,
    LeaderboardCategory,
    LeaderboardEntry,
    Scorecard,
    SubsystemMetric,
    TrendPoint,
    TrendReport,
    RegressionReport,
    CIComparison,
    CICheckResult,
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
from deephunter.evaluation.providers import (
    AIProvider,
    ProviderComparison,
    ProviderConfig,
    ProviderEvaluator,
    ProviderResult,
)
from deephunter.evaluation.datasets import (
    GOLDEN_DATASET_AUTH,
    GOLDEN_DATASET_CLOUD,
    GOLDEN_DATASET_LARAVEL,
    GOLDEN_DATASET_SQLI_XSS,
    GOLDEN_DATASET_SSRF,
    REGRESSION_DATASET_METHODOLOGY,
    REGRESSION_DATASET_PLANNER,
    REGRESSION_DATASET_TECH_INTEL,
)


class TestEvaluationReport:
    def test_default_init(self) -> None:
        report = EvaluationReport()
        assert report.precision == 0.0
        assert report.recall == 0.0
        assert report.f1 == 0.0
        assert report.hit_rate == 0.0
        assert report.num_queries == 0

    def test_to_dict(self) -> None:
        report = EvaluationReport(
            precision=0.8,
            recall=0.6,
            f1=0.6857,
            hit_rate=0.9,
            num_queries=10,
        )
        d = report.to_dict()
        assert d["precision"] == 0.8
        assert d["num_queries"] == 10


class TestEvaluator:
    def test_perfect_retrieval(self) -> None:
        evaluator = Evaluator()
        results: dict[str, list[str]] = {
            "query1": ["a", "b", "c"],
            "query2": ["d", "e"],
        }
        ground_truth: dict[str, set[str]] = {
            "query1": {"a", "b", "c"},
            "query2": {"d", "e"},
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.precision == 1.0
        assert report.recall == 1.0
        assert report.f1 == 1.0
        assert report.hit_rate == 1.0

    def test_no_relevant(self) -> None:
        evaluator = Evaluator()
        results: dict[str, list[str]] = {
            "query1": ["a", "b"],
        }
        ground_truth: dict[str, set[str]] = {
            "query1": {"c", "d"},
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.precision == 0.0
        assert report.recall == 0.0
        assert report.f1 == 0.0
        assert report.hit_rate == 0.0

    def test_partial_match(self) -> None:
        evaluator = Evaluator()
        results: dict[str, list[str]] = {
            "query1": ["a", "b", "c", "d"],
        }
        ground_truth: dict[str, set[str]] = {
            "query1": {"a", "b", "e"},
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.precision == 0.5  # 2/4
        assert pytest.approx(report.recall, 0.01) == 0.6667  # 2/3
        assert pytest.approx(report.f1, 0.01) == 0.5714

    def test_mixed_queries(self) -> None:
        evaluator = Evaluator()
        results: dict[str, list[str]] = {
            "q1": ["a", "b"],
            "q2": ["c", "d"],
            "q3": ["e", "f"],
        }
        ground_truth: dict[str, set[str]] = {
            "q1": {"a", "b"},  # perfect
            "q2": {"x", "y"},  # zero
            "q3": {"e"},  # partial recall
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.hit_rate == 2 / 3  # q1 and q3 hit
        assert report.precision > 0
        assert report.recall > 0

    def test_empty_retrieved(self) -> None:
        evaluator = Evaluator()
        results: dict[str, list[str]] = {
            "q1": [],
        }
        ground_truth: dict[str, set[str]] = {
            "q1": {"a"},
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.precision == 0.0
        assert report.recall == 0.0
        assert report.hit_rate == 0.0

    def test_empty_query_results(self) -> None:
        evaluator = Evaluator()
        with pytest.raises(EvaluationError, match="query_results must not be empty"):
            evaluator.evaluate_retrieval({}, {"q": {"a"}})

    def test_empty_ground_truth(self) -> None:
        evaluator = Evaluator()
        with pytest.raises(EvaluationError, match="ground_truth must not be empty"):
            evaluator.evaluate_retrieval({"q": ["a"]}, {})

    def test_multiple_queries_hit_rate(self) -> None:
        evaluator = Evaluator()
        results: dict[str, list[str]] = {
            "q1": ["a"],
            "q2": ["b"],
            "q3": ["c"],
            "q4": ["d"],
        }
        ground_truth: dict[str, set[str]] = {
            "q1": {"a"},
            "q2": {"x"},
            "q3": {"c"},
            "q4": {"x"},
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.hit_rate == 0.5  # 2/4
        assert report.num_queries == 4

    def test_details_length(self) -> None:
        evaluator = Evaluator()
        results: dict[str, list[str]] = {"q1": ["a"], "q2": ["b"]}
        ground_truth: dict[str, set[str]] = {"q1": {"a"}, "q2": {"b"}}
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert len(report.details) == 2


# =============================================================================
# New comprehensive tests for the evaluation framework
# =============================================================================


class TestBenchmarkDataset:
    def test_create_dataset(self) -> None:
        ds = BenchmarkDataset(name="Test", version="1.0.0")
        assert ds.name == "Test"
        assert ds.version == "1.0.0"
        assert ds.dataset_type == DatasetType.GOLDEN
        assert ds.entry_count() == 0
        assert ds.id is not None

    def test_dataset_versioning(self) -> None:
        ds1 = BenchmarkDataset(name="A", version="1.0.0")
        ds2 = BenchmarkDataset(name="A", version="2.0.0")
        assert ds1.version == "1.0.0"
        assert ds2.version == "2.0.0"
        assert ds1.version != ds2.version

    def test_filter_by_tag(self) -> None:
        entry_a = BenchmarkEntry(name="a", tags=["sql", "high"])
        entry_b = BenchmarkEntry(name="b", tags=["xss", "medium"])
        entry_c = BenchmarkEntry(name="c", tags=["sql", "low"])
        ds = BenchmarkDataset(entries=[entry_a, entry_b, entry_c])
        sql_entries = ds.by_tag("sql")
        assert len(sql_entries) == 2
        assert all("sql" in e.tags for e in sql_entries)

    def test_filter_by_difficulty(self) -> None:
        entries = [
            BenchmarkEntry(name="e1", difficulty="easy"),
            BenchmarkEntry(name="e2", difficulty="medium"),
            BenchmarkEntry(name="e3", difficulty="hard"),
            BenchmarkEntry(name="e4", difficulty="medium"),
        ]
        ds = BenchmarkDataset(entries=entries)
        medium = ds.by_difficulty("medium")
        assert len(medium) == 2
        assert all(e.difficulty == "medium" for e in medium)

    def test_filter_by_bug_class(self) -> None:
        entries = [
            BenchmarkEntry(name="e1", input=BenchmarkInput(bug_classes=["sqli"])),
            BenchmarkEntry(name="e2", input=BenchmarkInput(bug_classes=["xss"])),
            BenchmarkEntry(name="e3", input=BenchmarkInput(bug_classes=["sqli", "rce"])),
        ]
        ds = BenchmarkDataset(entries=entries)
        sqli = ds.by_bug_class("sqli")
        assert len(sqli) == 2

    def test_entry_count(self) -> None:
        ds = BenchmarkDataset(entries=[BenchmarkEntry() for _ in range(5)])
        assert ds.entry_count() == 5

    def test_serialization(self) -> None:
        ds = BenchmarkDataset(name="SerTest", version="1.2.3", entries=[BenchmarkEntry(name="e1")])
        dumped = ds.model_dump()
        assert dumped["name"] == "SerTest"
        assert dumped["version"] == "1.2.3"
        assert len(dumped["entries"]) == 1
        loaded = BenchmarkDataset.model_validate(dumped)
        assert loaded.name == ds.name
        assert loaded.entry_count() == ds.entry_count()


class TestBenchmarkEntry:
    def test_create_entry(self) -> None:
        entry = BenchmarkEntry(name="test-entry")
        assert entry.name == "test-entry"
        assert entry.difficulty == "medium"
        assert isinstance(entry.input, BenchmarkInput)
        assert isinstance(entry.expected, ExpectedOutput)
        assert entry.id is not None

    def test_entry_with_input(self) -> None:
        inp = BenchmarkInput(
            target_url="https://example.com",
            technologies=["Python", "Django"],
            bug_classes=["sqli"],
        )
        entry = BenchmarkEntry(name="sqli-test", input=inp, difficulty="hard")
        assert entry.input.target_url == "https://example.com"
        assert "Python" in entry.input.technologies
        assert entry.difficulty == "hard"

    def test_entry_with_expected_output(self) -> None:
        steps = [ExpectedStep(phase="test", title="Step 1", description="desc")]
        reason = ExpectedReasoning(hypotheses=["h1"], confidence=0.9)
        expected = ExpectedOutput(
            planner_steps=steps,
            technologies=["Go"],
            reasoning=reason,
            knowledge_packs=["go-security"],
        )
        entry = BenchmarkEntry(name="with-expected", expected=expected)
        assert len(entry.expected.planner_steps) == 1
        assert entry.expected.technologies == ["Go"]
        assert entry.expected.reasoning.confidence == 0.9

    def test_entry_empty_lists(self) -> None:
        entry = BenchmarkEntry()
        assert entry.tags == []
        assert entry.cwe_ids == []
        assert entry.input.technologies == []
        assert entry.input.bug_classes == []
        assert entry.expected.planner_steps == []
        assert entry.expected.knowledge_packs == []

    def test_entry_missing_fields(self) -> None:
        entry = BenchmarkEntry()
        assert entry.description == ""
        assert entry.bug_bounty_source == ""
        assert entry.input.target_url == ""
        assert entry.expected.reasoning.confidence == 0.0
        assert entry.expected.confidence == 1.0

    def test_entry_cwe_ids(self) -> None:
        entry = BenchmarkEntry(name="cwe-test", cwe_ids=["CWE-89", "CWE-79"])
        assert len(entry.cwe_ids) == 2
        assert "CWE-89" in entry.cwe_ids

    def test_entry_uuid_generation(self) -> None:
        e1 = BenchmarkEntry()
        e2 = BenchmarkEntry()
        assert e1.id != e2.id


class TestScoringEngine:
    def test_perfect_match(self) -> None:
        entry = BenchmarkEntry(
            name="perfect",
            expected=ExpectedOutput(
                planner_steps=[ExpectedStep(phase="p", title="Step1")],
                technologies=["a", "b"],
                frameworks=["django"],
                attack_surface=["login"],
                knowledge_packs=["kp1"],
                reasoning=ExpectedReasoning(hypotheses=["h1"]),
            ),
        )
        metrics = compute_metrics(
            entry,
            actual_planner_steps=[{"title": "Step1", "phase": "p"}],
            actual_technologies=["a", "b"],
            actual_frameworks=["django"],
            actual_attack_surface=["login"],
            actual_knowledge_packs=["kp1"],
            actual_reasoning=["h1"],
        )
        assert metrics.planner_accuracy.score == 1.0
        assert metrics.technology_accuracy.score == 1.0
        assert metrics.framework_accuracy.score == 1.0

    def test_partial_match(self) -> None:
        entry = BenchmarkEntry(
            name="partial",
            expected=ExpectedOutput(
                technologies=["a", "b", "c"],
                frameworks=["django", "flask"],
            ),
        )
        metrics = compute_metrics(
            entry,
            actual_planner_steps=[],
            actual_technologies=["a", "d"],
            actual_frameworks=["django"],
            actual_attack_surface=[],
            actual_knowledge_packs=[],
            actual_reasoning=[],
        )
        assert 0.0 < metrics.technology_accuracy.score < 1.0
        assert metrics.framework_accuracy.score > 0.0

    def test_no_match(self) -> None:
        entry = BenchmarkEntry(
            name="no-match",
            expected=ExpectedOutput(
                technologies=["x", "y"],
                frameworks=["express"],
                attack_surface=["admin"],
                knowledge_packs=["kp-a"],
                reasoning=ExpectedReasoning(hypotheses=["h-x"]),
            ),
        )
        metrics = compute_metrics(
            entry,
            actual_planner_steps=[],
            actual_technologies=["a"],
            actual_frameworks=["django"],
            actual_attack_surface=["public"],
            actual_knowledge_packs=["kp-b"],
            actual_reasoning=["h-y"],
        )
        assert metrics.technology_accuracy.score == 0.0
        assert metrics.framework_accuracy.score == 0.0

    def test_empty_expected(self) -> None:
        entry = BenchmarkEntry(name="empty-expected")
        metrics = compute_metrics(
            entry,
            actual_planner_steps=[{"title": "X"}],
            actual_technologies=["a"],
            actual_frameworks=["f"],
            actual_attack_surface=["s"],
            actual_knowledge_packs=["k"],
            actual_reasoning=["r"],
        )
        assert metrics.planner_accuracy.score == 1.0
        assert metrics.technology_accuracy.score == 0.0

    def test_empty_actual(self) -> None:
        entry = BenchmarkEntry(
            name="no-actual",
            expected=ExpectedOutput(
                technologies=["a", "b"],
                frameworks=["django"],
            ),
        )
        metrics = compute_metrics(
            entry,
            actual_planner_steps=[],
            actual_technologies=[],
            actual_frameworks=[],
            actual_attack_surface=[],
            actual_knowledge_packs=[],
            actual_reasoning=[],
        )
        assert metrics.technology_accuracy.score == 0.0
        assert metrics.framework_accuracy.score == 0.0

    def test_evaluate_entry(self) -> None:
        entry = BenchmarkEntry(name="eval-entry")
        result = evaluate_entry(
            entry,
            actual_planner_steps=[],
            actual_technologies=[],
            actual_frameworks=[],
            actual_attack_surface=[],
            actual_knowledge_packs=[],
            actual_reasoning=[],
            duration_ms=100.0,
            memory_bytes=1024,
            provider="test",
        )
        assert result.entry_name == "eval-entry"
        assert result.duration_ms == 100.0
        assert result.memory_usage_bytes == 1024
        assert result.provider == "test"

    def test_subsystem_metric_creation(self) -> None:
        m = SubsystemMetric(name="test", score=0.85, weight=0.5, threshold=0.3, passed=True)
        assert m.score == 0.85
        assert m.weight == 0.5
        assert m.passed is True


class TestBenchmarkRunner:
    def test_run_entry(self) -> None:
        def callback(_entry: BenchmarkEntry) -> dict:
            return {
                "planner_steps": [{"title": "Step1", "phase": "p"}],
                "technologies": ["Python"],
                "frameworks": ["django"],
                "attack_surface": ["login"],
                "knowledge_packs": [],
                "reasoning": [],
            }
        runner = BenchmarkRunner(callback=callback)
        entry = BenchmarkEntry(
            name="test-entry",
            input=BenchmarkInput(technologies=["Python"]),
            expected=ExpectedOutput(
                planner_steps=[ExpectedStep(phase="p", title="Step1")],
                technologies=["Python"],
                frameworks=["django"],
                attack_surface=["login"],
            ),
        )
        result = runner.run_entry(entry, provider="unittest")
        assert result.entry_name == "test-entry"
        assert result.provider == "unittest"

    def test_run_entry_no_callback(self) -> None:
        runner = BenchmarkRunner()
        with pytest.raises(RuntimeError, match="No callback set"):
            runner.run_entry(BenchmarkEntry())

    def test_run_entry_callback_error(self) -> None:
        def failing_cb(_entry: BenchmarkEntry) -> dict:
            msg = "callback failure"
            raise RuntimeError(msg)
        runner = BenchmarkRunner(callback=failing_cb)
        result = runner.run_entry(BenchmarkEntry(name="failing"))
        assert result.passed is False
        assert len(result.errors) > 0
        assert "callback failure" in result.errors[0]

    def test_run_dataset(self) -> None:
        def cb(_e: BenchmarkEntry) -> dict:
            return {
                "planner_steps": [{"title": "S1", "phase": "p"}],
                "technologies": ["Py"],
                "frameworks": [],
                "attack_surface": [],
                "knowledge_packs": [],
                "reasoning": [],
            }
        runner = BenchmarkRunner(callback=cb)
        entries = [
            BenchmarkEntry(name="e1", expected=ExpectedOutput(planner_steps=[ExpectedStep(phase="p", title="S1")], technologies=["Py"])),
            BenchmarkEntry(name="e2", expected=ExpectedOutput(planner_steps=[ExpectedStep(phase="p", title="S1")], technologies=["Py"])),
        ]
        ds = BenchmarkDataset(name="test-ds", entries=entries)
        suite = runner.run_dataset(ds, provider="test")
        assert suite.suite_name == "test-ds"
        assert suite.total_entries == 2
        assert suite.provider == "test"

    def test_run_empty_dataset(self) -> None:
        def cb(_e: BenchmarkEntry) -> dict:
            return {}
        runner = BenchmarkRunner(callback=cb)
        ds = BenchmarkDataset(name="empty", entries=[])
        suite = runner.run_dataset(ds)
        assert suite.total_entries == 0
        assert suite.overall_score == 0.0
        assert suite.pass_rate() == 0.0

    def test_run_filtered(self) -> None:
        def cb(_e: BenchmarkEntry) -> dict:
            return {"planner_steps": [], "technologies": [], "frameworks": [], "attack_surface": [], "knowledge_packs": [], "reasoning": []}
        runner = BenchmarkRunner(callback=cb)
        entries = [
            BenchmarkEntry(name="sqli-1", tags=["sql"], difficulty="easy", input=BenchmarkInput(bug_classes=["sqli"])),
            BenchmarkEntry(name="xss-1", tags=["xss"], difficulty="medium", input=BenchmarkInput(bug_classes=["xss"])),
            BenchmarkEntry(name="sqli-2", tags=["sql"], difficulty="hard", input=BenchmarkInput(bug_classes=["sqli"])),
        ]
        ds = BenchmarkDataset(name="filter-ds", entries=entries)
        filtered = runner.run_filtered(ds, tags=["sql"])
        assert filtered.total_entries == 2
        assert filtered.suite_name.endswith("(filtered)")

    def test_run_regression(self) -> None:
        def cb(_e: BenchmarkEntry) -> dict:
            return {"planner_steps": [{"title": "S1"}], "technologies": ["Py"], "frameworks": [], "attack_surface": [], "knowledge_packs": [], "reasoning": []}
        runner = BenchmarkRunner(callback=cb)
        e = BenchmarkEntry(name="reg-entry", expected=ExpectedOutput(planner_steps=[ExpectedStep(title="S1")], technologies=["Py"]))
        ds = BenchmarkDataset(name="reg-ds", entries=[e])
        result, info = runner.run_regression(ds)
        assert result.total_entries == 1
        assert "regressed" in info

    def test_to_scorecard(self) -> None:
        def cb(_e: BenchmarkEntry) -> dict:
            return {"planner_steps": [], "technologies": [], "frameworks": [], "attack_surface": [], "knowledge_packs": [], "reasoning": []}
        runner = BenchmarkRunner(callback=cb)
        entry = BenchmarkEntry(name="sc-entry")
        ds = BenchmarkDataset(entries=[entry])
        suite = runner.run_dataset(ds)
        sc = runner.to_scorecard(suite)
        assert sc.name == suite.suite_name
        assert sc.overall_score == suite.overall_score
        assert sc.total_tests == 1


class TestReporters:
    def test_json_reporter_suite(self) -> None:
        reporter = JSONReporter()
        result = BenchmarkSuiteResult(suite_name="json-test", total_entries=3, passed=2, failed=1)
        output = reporter.generate(result)
        assert '"suite_name": "json-test"' in output
        assert '"total_entries": 3' in output

    def test_json_reporter_scorecard(self) -> None:
        reporter = JSONReporter()
        sc = Scorecard(name="sc-test", overall_score=0.85, pass_rate=0.9)
        output = reporter.generate(sc)
        assert '"overall_score": 0.85' in output

    def test_json_reporter_trend(self) -> None:
        reporter = JSONReporter()
        trend = TrendReport(name="trend-test", score_delta=0.05)
        output = reporter.generate(trend)
        assert '"name": "trend-test"' in output

    def test_markdown_reporter_scorecard(self) -> None:
        reporter = MarkdownReporter()
        sc = Scorecard(name="md-sc", overall_score=0.75, pass_rate=0.8, passed=4, failed=1, total_tests=5, duration_ms=100.0)
        output = reporter.generate(sc)
        assert "# Scorecard: md-sc" in output
        assert "75.0%" in output or "75%" in output

    def test_markdown_reporter_suite(self) -> None:
        reporter = MarkdownReporter()
        result = BenchmarkSuiteResult(suite_name="md-suite", total_entries=2, passed=1, failed=1)
        output = reporter.generate(result)
        assert "# Suite: md-suite" in output

    def test_markdown_reporter_trend(self) -> None:
        reporter = MarkdownReporter()
        trend = TrendReport(name="md-trend", score_delta=-0.1, regression_detected=True)
        output = reporter.generate(trend)
        assert "# Trend: md-trend" in output
        assert "Regression Detected" in output

    def test_markdown_reporter_regression(self) -> None:
        reporter = MarkdownReporter()
        reg = RegressionReport(suite_name="reg-test", regressed=True, new_failures=["e1"])
        output = reporter.generate(reg)
        assert "Regression Report: reg-test" in output

    def test_markdown_reporter_leaderboard(self) -> None:
        reporter = MarkdownReporter()
        lb = Leaderboard(name="lb-test", category=LeaderboardCategory.BEST_OVERALL,
                         entries=[LeaderboardEntry(rank=1, name="provider-a", score=0.9, pass_rate=0.8, avg_latency_ms=100.0)])
        output = reporter.generate(lb)
        assert "# Leaderboard: lb-test" in output

    def test_html_reporter_suite(self) -> None:
        reporter = HTMLReporter()
        result = BenchmarkSuiteResult(suite_name="html-suite", total_entries=1, passed=1, failed=0)
        output = reporter.generate(result)
        assert "<h1>Suite: html-suite</h1>" in output
        assert "<!DOCTYPE html>" in output

    def test_html_reporter_leaderboard(self) -> None:
        reporter = HTMLReporter()
        lb = Leaderboard(name="html-lb", category=LeaderboardCategory.BEST_OVERALL,
                         entries=[LeaderboardEntry(rank=1, name="p1", score=0.95, pass_rate=0.9, avg_latency_ms=50.0)])
        output = reporter.generate(lb)
        assert "Leaderboard: html-lb" in output

    def test_csv_reporter_metrics(self) -> None:
        reporter = CSVReporter()
        results = [BenchmarkSuiteResult(suite_name="csv-suite", overall_score=0.8, passed=5, failed=1, total_entries=6, duration_ms=200.0, provider="test")]
        output = reporter.generate(results)
        assert "csv-suite" in output
        assert "0.8" in output

    def test_csv_reporter_leaderboard(self) -> None:
        reporter = CSVReporter()
        lb = Leaderboard(name="csv-lb", category=LeaderboardCategory.BEST_OVERALL,
                         entries=[LeaderboardEntry(rank=1, name="p1", score=0.9, pass_rate=0.85, avg_latency_ms=100.0, entries_evaluated=5)])
        output = reporter.generate(lb)
        assert "p1" in output
        assert "0.9" in output

    def test_report_writer_write_all(self, tmp_path: str) -> None:
        writer = ReportWriter(output_dir=str(tmp_path))
        result = BenchmarkSuiteResult(suite_name="write-all-test", total_entries=1, passed=1, failed=0)
        paths = writer.write_all(result)
        assert "json" in paths
        assert "md" in paths
        assert "html" in paths


class TestLeaderboard:
    def test_single_result(self) -> None:
        gen = LeaderboardGenerator()
        result = BenchmarkSuiteResult(suite_name="single", overall_score=0.85, total_entries=5, passed=4, failed=1, duration_ms=500.0)
        lb = gen.generate([result], LeaderboardCategory.BEST_OVERALL)
        assert lb.total_ranked == 1
        assert lb.entries[0].rank == 1
        assert lb.entries[0].score == 0.85

    def test_multiple_results(self) -> None:
        gen = LeaderboardGenerator()
        r1 = BenchmarkSuiteResult(suite_name="a", overall_score=0.9, total_entries=10, passed=9, failed=1, duration_ms=1000.0)
        r2 = BenchmarkSuiteResult(suite_name="b", overall_score=0.7, total_entries=10, passed=7, failed=3, duration_ms=800.0)
        lb = gen.generate([r1, r2], LeaderboardCategory.BEST_OVERALL)
        assert lb.total_ranked == 2
        assert lb.entries[0].name == "a"
        assert lb.entries[0].score == 0.9

    def test_all_categories(self) -> None:
        gen = LeaderboardGenerator()
        r = BenchmarkSuiteResult(suite_name="all-cat", overall_score=0.8, total_entries=2, passed=2, failed=0, duration_ms=200.0)
        cats = gen.generate_all_categories([r])
        assert len(cats) == len(LeaderboardCategory)
        for cat in LeaderboardCategory:
            assert cat in cats

    def test_tie_breaking(self) -> None:
        gen = LeaderboardGenerator()
        r1 = BenchmarkSuiteResult(suite_name="first", overall_score=0.8, total_entries=10, passed=8, failed=2, duration_ms=500.0)
        r2 = BenchmarkSuiteResult(suite_name="second", overall_score=0.8, total_entries=10, passed=8, failed=2, duration_ms=600.0)
        lb = gen.generate([r1, r2], LeaderboardCategory.BEST_OVERALL)
        assert lb.entries[0].rank == 1
        assert lb.entries[1].rank == 2
        assert lb.entries[0].score == lb.entries[1].score

    def test_empty_results(self) -> None:
        gen = LeaderboardGenerator()
        lb = gen.generate([], LeaderboardCategory.BEST_OVERALL)
        assert lb.total_ranked == 0
        assert lb.entries == []

    def test_rank_by_planner(self) -> None:
        gen = LeaderboardGenerator()
        r = BenchmarkSuiteResult(suite_name="plan-test", overall_score=0.5, total_entries=2, passed=1, failed=1, duration_ms=100.0,
                                 results=[EvaluationResult(entry_id="e1", entry_name="e1",
                                                           metrics=EvaluationMetrics(planner_accuracy=SubsystemMetric(name="planner_accuracy", score=0.9, weight=1.0, passed=True))),
                                          EvaluationResult(entry_id="e2", entry_name="e2",
                                                           metrics=EvaluationMetrics(planner_accuracy=SubsystemMetric(name="planner_accuracy", score=0.7, weight=1.0, passed=True)))])
        lb = gen.generate([r], LeaderboardCategory.BEST_PLANNER)
        assert lb.total_ranked == 1
        assert lb.entries[0].score == 0.8

    def test_rank_by_provider(self) -> None:
        gen = LeaderboardGenerator()
        r1 = BenchmarkSuiteResult(suite_name="p1", overall_score=0.9, total_entries=5, passed=5, failed=0, duration_ms=500.0, provider="openai")
        r2 = BenchmarkSuiteResult(suite_name="p2", overall_score=0.7, total_entries=5, passed=4, failed=1, duration_ms=400.0, provider="deepseek")
        lb = gen.generate([r1, r2], LeaderboardCategory.BEST_PROVIDER)
        assert lb.total_ranked == 2
        assert lb.entries[0].name == "openai"


class TestCIIntegration:
    def test_quality_gate_pass(self) -> None:
        ci = CIIntegration(artifacts_dir="/tmp/opencode/evaluation/test_ci")
        result = BenchmarkSuiteResult(suite_name="gate", overall_score=0.85, total_entries=10, passed=8, failed=2, duration_ms=500.0)
        check = ci.run_quality_gate(result, threshold=0.7)
        assert check.passed is True
        assert check.score == 0.85

    def test_quality_gate_fail(self) -> None:
        ci = CIIntegration(artifacts_dir="/tmp/opencode/evaluation/test_ci")
        result = BenchmarkSuiteResult(suite_name="gate-fail", overall_score=0.5, total_entries=10, passed=4, failed=6, duration_ms=500.0)
        check = ci.run_quality_gate(result, threshold=0.7)
        assert check.passed is False
        assert check.score == 0.5

    def test_save_and_load_result(self) -> None:
        ci = CIIntegration(artifacts_dir="/tmp/opencode/evaluation/test_ci")
        result = BenchmarkSuiteResult(suite_name="save-load", overall_score=0.9, total_entries=1, passed=1, failed=0, duration_ms=100.0)
        path = ci.save_current_result(result)
        loaded = ci.load_previous_result(path)
        assert loaded is not None
        assert loaded.suite_name == "save-load"
        assert loaded.overall_score == 0.9

    def test_compare_with_previous(self) -> None:
        ci = CIIntegration(artifacts_dir="/tmp/opencode/evaluation/test_ci")
        prev = BenchmarkSuiteResult(id="prev-1", suite_name="comp", overall_score=0.8, total_entries=2, passed=2, failed=0,
                                    results=[EvaluationResult(entry_id="e1", entry_name="e1", passed=True)])
        ci.save_current_result(prev)
        curr = BenchmarkSuiteResult(id="curr-1", suite_name="comp", overall_score=0.9, total_entries=2, passed=2, failed=0,
                                    results=[EvaluationResult(entry_id="e1", entry_name="e1", passed=True)])
        comp = ci.compare_with_previous(curr)
        assert comp.previous_run_id == "prev-1"
        assert comp.current_run_id == "curr-1"
        assert comp.score_change == 0.1

    def test_should_fail_pipeline(self) -> None:
        ci = CIIntegration()
        passed_check = CICheckResult(passed=True, score=0.9, threshold=0.7, regressions_detected=0)
        assert ci.should_fail_pipeline(passed_check) is False
        failed_check = CICheckResult(passed=False, score=0.5, threshold=0.7, regressions_detected=0)
        assert ci.should_fail_pipeline(failed_check) is True
        regressed = CICheckResult(passed=True, score=0.8, threshold=0.7, regressions_detected=2)
        assert ci.should_fail_pipeline(regressed, fail_on_regression=True) is True
        assert ci.should_fail_pipeline(regressed, fail_on_regression=False) is False

    def test_environment_detection(self) -> None:
        env = CIIntegration.detect_ci_environment()
        assert env in ("github_actions", "gitlab_ci", "jenkins", "circleci", "local")

    def test_generate_ci_summary(self) -> None:
        ci = CIIntegration()
        result = BenchmarkSuiteResult(suite_name="ci-summary", overall_score=0.88, total_entries=5, passed=4, failed=1, duration_ms=300.0)
        check = CICheckResult(passed=True, score=0.88, threshold=0.7)
        summary = ci.generate_ci_summary(result, check)
        assert "DeepHunter Evaluation Summary" in summary
        assert "PASSED" in summary

    def test_regression_detection(self) -> None:
        ci = CIIntegration(artifacts_dir="/tmp/opencode/evaluation/test_ci")
        prev = BenchmarkSuiteResult(id="prev-r", suite_name="reg-test", overall_score=0.9, total_entries=2, passed=2, failed=0,
                                    results=[EvaluationResult(entry_id="e1", entry_name="e1", passed=True),
                                             EvaluationResult(entry_id="e2", entry_name="e2", passed=True)])
        ci.save_current_result(prev)
        curr = BenchmarkSuiteResult(id="curr-r", suite_name="reg-test", overall_score=0.7, total_entries=2, passed=0, failed=2,
                                    results=[EvaluationResult(entry_id="e1", entry_name="e1", passed=False),
                                             EvaluationResult(entry_id="e2", entry_name="e2", passed=False)])
        comp = ci.compare_with_previous(curr)
        assert comp.score_change < 0
        assert len(comp.regressions) > 0


class TestBuiltInDatasets:
    def test_golden_sqli_xss(self) -> None:
        ds = GOLDEN_DATASET_SQLI_XSS
        assert ds.name == "Golden: SQL Injection & XSS"
        assert ds.version == "1.0.0"
        assert ds.dataset_type == DatasetType.GOLDEN
        assert ds.entry_count() >= 3
        assert all(isinstance(e, BenchmarkEntry) for e in ds.entries)

    def test_golden_auth(self) -> None:
        ds = GOLDEN_DATASET_AUTH
        assert ds.name == "Golden: Authentication & Authorization"
        assert ds.dataset_type == DatasetType.GOLDEN
        assert ds.entry_count() >= 2
        assert any("auth" in t for t in ds.tags)

    def test_golden_ssrf(self) -> None:
        ds = GOLDEN_DATASET_SSRF
        assert "Golden: Server-Side Request Forgery" in ds.name
        assert ds.entry_count() >= 1
        assert "ssrf" in ds.tags

    def test_golden_laravel(self) -> None:
        ds = GOLDEN_DATASET_LARAVEL
        assert "Laravel" in ds.name
        assert ds.entry_count() >= 2
        for e in ds.entries:
            assert "laravel" in e.input.frameworks or "laravel" in " ".join(e.tags)

    def test_golden_cloud(self) -> None:
        ds = GOLDEN_DATASET_CLOUD
        assert "Cloud" in ds.name
        assert ds.entry_count() >= 2
        assert ds.dataset_type == DatasetType.GOLDEN

    def test_regression_planner(self) -> None:
        ds = REGRESSION_DATASET_PLANNER
        assert "Planner" in ds.name
        assert ds.dataset_type == DatasetType.REGRESSION
        assert ds.entry_count() >= 2

    def test_regression_methodology(self) -> None:
        ds = REGRESSION_DATASET_METHODOLOGY
        assert "Methodology" in ds.name
        assert ds.entry_count() >= 1

    def test_regression_tech_intel(self) -> None:
        ds = REGRESSION_DATASET_TECH_INTEL
        assert "Technology Intelligence" in ds.name or "Tech Intel" in ds.name
        assert ds.entry_count() >= 1
        assert "regression" in ds.tags

    def test_all_datasets_have_valid_structure(self) -> None:
        for ds in [GOLDEN_DATASET_SQLI_XSS, GOLDEN_DATASET_AUTH, GOLDEN_DATASET_SSRF,
                   GOLDEN_DATASET_LARAVEL, GOLDEN_DATASET_CLOUD,
                   REGRESSION_DATASET_PLANNER, REGRESSION_DATASET_METHODOLOGY,
                   REGRESSION_DATASET_TECH_INTEL]:
            assert isinstance(ds, BenchmarkDataset)
            assert ds.id is not None
            assert ds.name != ""
            assert ds.version != ""
            for e in ds.entries:
                assert isinstance(e, BenchmarkEntry)
                assert isinstance(e.input, BenchmarkInput)
                assert isinstance(e.expected, ExpectedOutput)


class TestEdgeCases:
    def test_empty_dataset(self) -> None:
        ds = BenchmarkDataset(name="empty", entries=[])
        assert ds.entry_count() == 0
        assert ds.by_tag("any") == []
        assert ds.by_difficulty("easy") == []
        assert ds.by_bug_class("sqli") == []

    def test_empty_entry_list(self) -> None:
        ds = BenchmarkDataset(entries=[])
        assert ds.entry_count() == 0

    def test_entry_with_null_lists(self) -> None:
        entry = BenchmarkEntry(tags=[], cwe_ids=[], input=BenchmarkInput(technologies=[], bug_classes=[]))
        assert entry.tags == []
        assert entry.cwe_ids == []
        assert entry.input.technologies == []

    def test_very_large_scores(self) -> None:
        m = SubsystemMetric(name="big", score=1e6, weight=1e3, threshold=0.0)
        assert m.score == 1e6
        assert m.weight == 1e3
        metrics = EvaluationMetrics(planner_accuracy=m)
        overall = metrics.overall_score()
        assert overall > 0

    def test_dataset_versioning_comparison(self) -> None:
        v1 = BenchmarkDataset(name="v", version="1.0.0", entries=[BenchmarkEntry(name="e1")])
        v2 = BenchmarkDataset(name="v", version="2.0.0", entries=[BenchmarkEntry(name="e1"), BenchmarkEntry(name="e2")])
        assert v1.version == "1.0.0"
        assert v2.version == "2.0.0"
        assert v1.entry_count() < v2.entry_count()

    def test_scorecard_with_zero_tests(self) -> None:
        sc = Scorecard(name="zero", total_tests=0, passed=0, failed=0)
        assert sc.pass_rate == 0.0
        assert sc.overall_score == 0.0

    def test_suite_result_with_no_results(self) -> None:
        sr = BenchmarkSuiteResult(suite_name="no-res", total_entries=0, passed=0, failed=0)
        assert sr.pass_rate() == 0.0
        assert sr.overall_score == 0.0

    def test_entry_with_all_defaults_roundtrips(self) -> None:
        entry = BenchmarkEntry()
        dumped = entry.model_dump()
        loaded = BenchmarkEntry.model_validate(dumped)
        assert loaded.id == entry.id
        assert loaded.name == entry.name
        assert loaded.difficulty == entry.difficulty

    def test_negative_duration(self) -> None:
        result = EvaluationResult(entry_id="e1", duration_ms=-1.0, passed=False)
        assert result.duration_ms == -1.0


class TestSubsystemMetrics:
    def test_create_evaluation_metrics(self) -> None:
        em = EvaluationMetrics()
        assert isinstance(em.planner_accuracy, SubsystemMetric)
        assert em.planner_accuracy.name == ""
        assert em.technology_accuracy.name == ""

    def test_overall_score_perfect(self) -> None:
        perfect = lambda n: SubsystemMetric(name=n, score=1.0, weight=1.0, passed=True)
        em = EvaluationMetrics(
            planner_accuracy=perfect("planner_accuracy"),
            technology_accuracy=perfect("technology_accuracy"),
            framework_accuracy=perfect("framework_accuracy"),
            methodology_coverage=perfect("methodology_coverage"),
            checklist_coverage=perfect("checklist_coverage"),
            reasoning_quality=perfect("reasoning_quality"),
            context_quality=perfect("context_quality"),
            prompt_quality=perfect("prompt_quality"),
            knowledge_pack_coverage=perfect("knowledge_pack_coverage"),
            attack_surface_coverage=perfect("attack_surface_coverage"),
            relationship_accuracy=perfect("relationship_accuracy"),
            latency_ms=perfect("latency_ms"),
            memory_bytes=perfect("memory_bytes"),
            throughput_eps=perfect("throughput_eps"),
        )
        assert em.overall_score() == 1.0

    def test_overall_score_mixed(self) -> None:
        em = EvaluationMetrics(
            planner_accuracy=SubsystemMetric(name="planner_accuracy", score=1.0, weight=1.0, passed=True),
            technology_accuracy=SubsystemMetric(name="technology_accuracy", score=0.5, weight=0.8, passed=True),
            framework_accuracy=SubsystemMetric(name="framework_accuracy", score=0.0, weight=0.7, passed=False),
        )
        score = em.overall_score()
        assert 0.0 < score < 1.0

    def test_overall_score_zero_weight(self) -> None:
        em = EvaluationMetrics(
            planner_accuracy=SubsystemMetric(name="planner_accuracy", score=1.0, weight=0.0, passed=True),
        )
        assert em.overall_score() == 0.0

    def test_all_passed_true(self) -> None:
        def _p(name: str) -> SubsystemMetric:
            return SubsystemMetric(name=name, score=0.9, weight=1.0, passed=True)
        em = EvaluationMetrics(
            planner_accuracy=_p("planner_accuracy"),
            technology_accuracy=_p("technology_accuracy"),
            framework_accuracy=_p("framework_accuracy"),
            methodology_coverage=_p("methodology_coverage"),
            checklist_coverage=_p("checklist_coverage"),
            reasoning_quality=_p("reasoning_quality"),
            context_quality=_p("context_quality"),
            prompt_quality=_p("prompt_quality"),
            knowledge_pack_coverage=_p("knowledge_pack_coverage"),
            attack_surface_coverage=_p("attack_surface_coverage"),
            relationship_accuracy=_p("relationship_accuracy"),
            latency_ms=_p("latency_ms"),
            memory_bytes=_p("memory_bytes"),
            throughput_eps=_p("throughput_eps"),
        )
        assert em.all_passed() is True

    def test_all_passed_false(self) -> None:
        def _p(name: str) -> SubsystemMetric:
            return SubsystemMetric(name=name, score=0.9, weight=1.0, passed=True)
        em = EvaluationMetrics(
            planner_accuracy=_p("p"),
            technology_accuracy=SubsystemMetric(name="t", score=0.2, weight=1.0, passed=False),
            framework_accuracy=_p("framework_accuracy"),
            methodology_coverage=_p("methodology_coverage"),
            checklist_coverage=_p("checklist_coverage"),
            reasoning_quality=_p("reasoning_quality"),
            context_quality=_p("context_quality"),
            prompt_quality=_p("prompt_quality"),
            knowledge_pack_coverage=_p("knowledge_pack_coverage"),
            attack_surface_coverage=_p("attack_surface_coverage"),
            relationship_accuracy=_p("relationship_accuracy"),
            latency_ms=_p("latency_ms"),
            memory_bytes=_p("memory_bytes"),
            throughput_eps=_p("throughput_eps"),
        )
        assert em.all_passed() is False

    def test_failed_metrics_reporting(self) -> None:
        def _p(name: str) -> SubsystemMetric:
            return SubsystemMetric(name=name, score=0.9, weight=1.0, passed=True)
        em = EvaluationMetrics(
            planner_accuracy=_p("planner_accuracy"),
            technology_accuracy=SubsystemMetric(name="technology_accuracy", score=0.1, weight=1.0, passed=False),
            framework_accuracy=SubsystemMetric(name="framework_accuracy", score=0.2, weight=1.0, passed=False),
            methodology_coverage=_p("methodology_coverage"),
            checklist_coverage=_p("checklist_coverage"),
            reasoning_quality=_p("reasoning_quality"),
            context_quality=_p("context_quality"),
            prompt_quality=_p("prompt_quality"),
            knowledge_pack_coverage=_p("knowledge_pack_coverage"),
            attack_surface_coverage=_p("attack_surface_coverage"),
            relationship_accuracy=_p("relationship_accuracy"),
            latency_ms=_p("latency_ms"),
            memory_bytes=_p("memory_bytes"),
            throughput_eps=_p("throughput_eps"),
        )
        failed = em.failed_metrics()
        assert "technology_accuracy" in failed
        assert "framework_accuracy" in failed
        assert "planner_accuracy" not in failed

    def test_failed_metrics_empty_when_all_pass(self) -> None:
        def _p(name: str) -> SubsystemMetric:
            return SubsystemMetric(name=name, score=0.9, weight=1.0, passed=True)
        em = EvaluationMetrics(
            planner_accuracy=_p("planner_accuracy"),
            technology_accuracy=_p("technology_accuracy"),
            framework_accuracy=_p("framework_accuracy"),
            methodology_coverage=_p("methodology_coverage"),
            checklist_coverage=_p("checklist_coverage"),
            reasoning_quality=_p("reasoning_quality"),
            context_quality=_p("context_quality"),
            prompt_quality=_p("prompt_quality"),
            knowledge_pack_coverage=_p("knowledge_pack_coverage"),
            attack_surface_coverage=_p("attack_surface_coverage"),
            relationship_accuracy=_p("relationship_accuracy"),
            latency_ms=_p("latency_ms"),
            memory_bytes=_p("memory_bytes"),
            throughput_eps=_p("throughput_eps"),
        )
        assert em.failed_metrics() == []
