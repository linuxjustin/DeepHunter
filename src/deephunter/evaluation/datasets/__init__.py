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
from deephunter.evaluation.datasets.knowledge_graph import (
    get_knowledge_graph_datasets,
    get_knowledge_graph_dataset,
    KNOWLEDGE_GRAPH_DATASET_LARAVEL,
    KNOWLEDGE_GRAPH_DATASET_NODEJS,
    KNOWLEDGE_GRAPH_DATASET_DATABASE,
    KNOWLEDGE_GRAPH_DATASET_CLOUD,
    KNOWLEDGE_GRAPH_DATASET_GRAPH_TRAVERSAL,
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
    "get_knowledge_graph_datasets",
    "get_knowledge_graph_dataset",
    "KNOWLEDGE_GRAPH_DATASET_LARAVEL",
    "KNOWLEDGE_GRAPH_DATASET_NODEJS",
    "KNOWLEDGE_GRAPH_DATASET_DATABASE",
    "KNOWLEDGE_GRAPH_DATASET_CLOUD",
    "KNOWLEDGE_GRAPH_DATASET_GRAPH_TRAVERSAL",
]
