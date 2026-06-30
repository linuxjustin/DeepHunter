"""Tests for app benchmarks (Sprint E)."""
from __future__ import annotations

import pytest

from deephunter.evaluation.datasets.app_benchmarks import (
    APP_BENCHMARKS,
    get_app_benchmark,
    get_app_benchmarks,
)


class TestAppBenchmarks:
    def test_all_benchmarks_present(self) -> None:
        entries = get_app_benchmarks()
        assert len(entries) == 7

    def test_benchmark_names(self) -> None:
        expected = {"juice_shop", "dvwa", "webgoat", "nodegoat", "vampi", "graphql_labs", "portswigger_academy"}
        assert set(APP_BENCHMARKS.keys()) == expected

    def test_get_benchmark_by_name(self) -> None:
        entry = get_app_benchmark("juice_shop")
        assert entry is not None
        assert "juice_shop" in entry.name

    def test_get_nonexistent(self) -> None:
        assert get_app_benchmark("nonexistent") is None

    @pytest.mark.parametrize("key", APP_BENCHMARKS.keys())
    def test_each_benchmark_has_expected_structure(self, key: str) -> None:
        entry = APP_BENCHMARKS[key]
        assert len(entry.description) > 0
        assert len(entry.input.bug_classes) > 0
        assert len(entry.input.technologies) > 0
        assert len(entry.expected.planner_steps) > 0
        assert len(entry.expected.reasoning.hypotheses) > 0
        assert len(entry.tags) > 0

    @pytest.mark.parametrize("key", APP_BENCHMARKS.keys())
    def test_each_benchmark_has_cwes(self, key: str) -> None:
        entry = APP_BENCHMARKS[key]
        assert len(entry.cwe_ids) > 0
        for cwe in entry.cwe_ids:
            assert cwe.startswith("CWE-")

    def test_juice_shop_comprehensive(self) -> None:
        entry = get_app_benchmark("juice_shop")
        assert entry is not None
        assert entry.difficulty == "hard"
        assert len(entry.input.bug_classes) >= 10
        assert len(entry.expected.planner_steps) >= 8
        assert len(entry.expected.reasoning.hypotheses) >= 5
