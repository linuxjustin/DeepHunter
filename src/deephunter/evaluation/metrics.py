"""Evaluation metrics for retrieval and reasoning quality.

Provides precision, recall, F1, and hit-rate calculations for
comparing generated hypotheses or retrieval results against
ground-truth annotations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from deephunter.core.config import EvaluationConfig
from deephunter.core.exceptions import EvaluationError
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class EvaluationReport:
    """Aggregated evaluation results across multiple queries."""

    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    hit_rate: float = 0.0
    num_queries: int = 0
    details: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "hit_rate": round(self.hit_rate, 4),
            "num_queries": self.num_queries,
        }


class Evaluator:
    """Computes evaluation metrics for retrieval and reasoning outputs.

    Supports:
    - Precision: fraction of retrieved items that are relevant.
    - Recall: fraction of relevant items that were retrieved.
    - F1: harmonic mean of precision and recall.
    - Hit rate: fraction of queries with at least one relevant result.
    """

    def __init__(self, config: Optional[EvaluationConfig] = None) -> None:
        self._config = config or EvaluationConfig()

    def evaluate_retrieval(
        self,
        query_results: Dict[str, List[str]],
        ground_truth: Dict[str, Set[str]],
    ) -> EvaluationReport:
        """Evaluate retrieval performance against ground truth.

        Args:
            query_results: Map of query -> list of retrieved SKO IDs.
            ground_truth: Map of query -> set of relevant SKO IDs.

        Returns:
            Aggregated EvaluationReport.

        Raises:
            EvaluationError: If inputs are empty or malformed.
        """
        if not query_results:
            raise EvaluationError("query_results must not be empty")
        if not ground_truth:
            raise EvaluationError("ground_truth must not be empty")

        precisions: List[float] = []
        recalls: List[float] = []
        hits = 0

        details: List[Dict] = []

        for query, retrieved in query_results.items():
            relevant = ground_truth.get(query, set())
            retrieved_set = set(retrieved)

            if not retrieved_set:
                precisions.append(0.0)
                recalls.append(0.0)
                details.append({
                    "query": query,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "hit": False,
                })
                continue

            true_positives = len(retrieved_set & relevant)

            precision = true_positives / len(retrieved_set) if retrieved_set else 0.0
            recall = true_positives / len(relevant) if relevant else 0.0
            f1_val = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0.0
            )

            precisions.append(precision)
            recalls.append(recall)

            if true_positives > 0:
                hits += 1

            details.append({
                "query": query,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1_val, 4),
                "hit": true_positives > 0,
            })

        num_queries = len(query_results)
        report = EvaluationReport(
            precision=sum(precisions) / num_queries,
            recall=sum(recalls) / num_queries,
            hit_rate=hits / num_queries,
            num_queries=num_queries,
            details=details,
        )

        if precisions or recalls:
            report.f1 = (
                2 * report.precision * report.recall / (report.precision + report.recall)
                if (report.precision + report.recall) > 0
                else 0.0
            )

        logger.info(
            "Evaluation: P=%.4f R=%.4f F1=%.4f HR=%.4f",
            report.precision,
            report.recall,
            report.f1,
            report.hit_rate,
        )
        return report