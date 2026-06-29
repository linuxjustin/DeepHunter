"""Tests for the evaluation framework."""

from __future__ import annotations

from typing import Dict, List, Set

import pytest

from deephunter.core.exceptions import EvaluationError
from deephunter.evaluation.metrics import Evaluator, EvaluationReport


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
        results: Dict[str, List[str]] = {
            "query1": ["a", "b", "c"],
            "query2": ["d", "e"],
        }
        ground_truth: Dict[str, Set[str]] = {
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
        results: Dict[str, List[str]] = {
            "query1": ["a", "b"],
        }
        ground_truth: Dict[str, Set[str]] = {
            "query1": {"c", "d"},
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.precision == 0.0
        assert report.recall == 0.0
        assert report.f1 == 0.0
        assert report.hit_rate == 0.0

    def test_partial_match(self) -> None:
        evaluator = Evaluator()
        results: Dict[str, List[str]] = {
            "query1": ["a", "b", "c", "d"],
        }
        ground_truth: Dict[str, Set[str]] = {
            "query1": {"a", "b", "e"},
        }
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert report.precision == 0.5  # 2/4
        assert pytest.approx(report.recall, 0.01) == 0.6667  # 2/3
        assert pytest.approx(report.f1, 0.01) == 0.5714

    def test_mixed_queries(self) -> None:
        evaluator = Evaluator()
        results: Dict[str, List[str]] = {
            "q1": ["a", "b"],
            "q2": ["c", "d"],
            "q3": ["e", "f"],
        }
        ground_truth: Dict[str, Set[str]] = {
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
        results: Dict[str, List[str]] = {
            "q1": [],
        }
        ground_truth: Dict[str, Set[str]] = {
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
        results: Dict[str, List[str]] = {
            "q1": ["a"],
            "q2": ["b"],
            "q3": ["c"],
            "q4": ["d"],
        }
        ground_truth: Dict[str, Set[str]] = {
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
        results: Dict[str, List[str]] = {"q1": ["a"], "q2": ["b"]}
        ground_truth: Dict[str, Set[str]] = {"q1": {"a"}, "q2": {"b"}}
        report = evaluator.evaluate_retrieval(results, ground_truth)
        assert len(report.details) == 2