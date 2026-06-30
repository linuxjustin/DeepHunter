"""Built-in benchmark datasets for the Evaluation Framework."""

from deephunter.evaluation.datasets.golden import (
    GOLDEN_DATASET_SQLI_XSS,
    GOLDEN_DATASET_AUTH,
    GOLDEN_DATASET_SSRF,
    GOLDEN_DATASET_LARAVEL,
    GOLDEN_DATASET_CLOUD,
)
from deephunter.evaluation.datasets.regression import (
    REGRESSION_DATASET_PLANNER,
    REGRESSION_DATASET_METHODOLOGY,
    REGRESSION_DATASET_TECH_INTEL,
)
from deephunter.evaluation.datasets.app_benchmarks import (
    get_app_benchmarks,
    get_app_benchmark,
    APP_BENCHMARKS,
)

__all__ = [
    "GOLDEN_DATASET_SQLI_XSS",
    "GOLDEN_DATASET_AUTH",
    "GOLDEN_DATASET_SSRF",
    "GOLDEN_DATASET_LARAVEL",
    "GOLDEN_DATASET_CLOUD",
    "REGRESSION_DATASET_PLANNER",
    "REGRESSION_DATASET_METHODOLOGY",
    "REGRESSION_DATASET_TECH_INTEL",
    "get_app_benchmarks",
    "get_app_benchmark",
    "APP_BENCHMARKS",
]
