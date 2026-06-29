"""Dataset builder — generates training samples from SKOs and hypotheses.

Produces structured datasets suitable for fine-tuning LLMs on
security knowledge, hypothesis generation, or retrieval tasks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from deephunter.core.config import TrainingConfig
from deephunter.core.exceptions import TrainingError
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.reasoning.hypothesis import Hypothesis, HypothesisGenerator
from deephunter.utils.files import ensure_dir
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DatasetSample:
    """A single training sample with input and expected output."""

    instruction: str
    input: str
    output: str
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instruction": self.instruction,
            "input": self.input,
            "output": self.output,
            "source": self.source,
            "metadata": self.metadata,
        }


class DatasetBuilder:
    """Builds training datasets from the knowledge store.

    Generates samples for:
    - Knowledge extraction (SKO -> QA pairs)
    - Hypothesis generation (context -> hypotheses)
    - Bug class classification (text -> bug class)
    - Retrieval (query -> relevant SKO)

    Usage::

        builder = DatasetBuilder(store, hypothesis_generator, config.training)
        samples = builder.build_knowledge_samples()
        builder.save(samples, "datasets/processed/knowledge.jsonl")
    """

    def __init__(
        self,
        store: KnowledgeStore,
        hypothesis_generator: Optional[HypothesisGenerator] = None,
        config: Optional[TrainingConfig] = None,
    ) -> None:
        self._store = store
        self._hypothesis_generator = hypothesis_generator
        self._config = config or TrainingConfig()

    def build_knowledge_samples(self) -> List[DatasetSample]:
        """Build QA samples from SKO summaries and content.

        Each SKO produces one or more samples:
        - "Summarize this security knowledge" -> SKO summary
        - "What bug classes are covered?" -> SKO bug classes

        Returns:
            List of DatasetSample objects.
        """
        samples: List[DatasetSample] = []
        for sko in self._store.list_all():
            content = sko.raw_content or f"{sko.title}: {sko.summary}"
            if not content.strip():
                continue

            samples.append(
                DatasetSample(
                    instruction="Summarize the following security knowledge",
                    input=content[:2000],
                    output=sko.summary or sko.title,
                    source=sko.source,
                    metadata={"sko_id": sko.id, "type": "summarization"},
                )
            )

            if sko.bug_classes:
                bc_list = ", ".join(b.value for b in sko.bug_classes)
                samples.append(
                    DatasetSample(
                        instruction="Identify bug classes in this security context",
                        input=content[:1500],
                        output=bc_list,
                        source=sko.source,
                        metadata={
                            "sko_id": sko.id,
                            "type": "bug_classification",
                        },
                    )
                )

        logger.info("Built %d knowledge samples", len(samples))
        return samples

    def build_hypothesis_samples(self, context: str = "web application security") -> List[DatasetSample]:
        """Build samples from generated hypotheses.

        Args:
            context: Research focus context for hypothesis generation.

        Returns:
            List of DatasetSample objects.

        Raises:
            TrainingError: If no hypothesis generator is configured.
        """
        if self._hypothesis_generator is None:
            raise TrainingError(
                "HypothesisGenerator is required to build hypothesis samples"
            )

        hypotheses = self._hypothesis_generator.generate(context)
        samples: List[DatasetSample] = []

        for hyp in hypotheses:
            bc_str = ", ".join(b.value for b in hyp.bug_classes)
            samples.append(
                DatasetSample(
                    instruction=f"Generate a hypothesis for {context}",
                    input=f"Target context: {context}",
                    output=(
                        f"Title: {hyp.title}\n"
                        f"Description: {hyp.description}\n"
                        f"Bug classes: {bc_str}\n"
                        f"Rationale: {hyp.rationale}\n"
                        f"Testing ideas: {'; '.join(hyp.testing_ideas)}"
                    ),
                    source="hypothesis_generator",
                    metadata={
                        "hypothesis_id": hyp.id,
                        "type": "hypothesis",
                        "priority": hyp.priority.value,
                    },
                )
            )

        logger.info("Built %d hypothesis samples", len(samples))
        return samples

    def build_text_samples(self) -> List[DatasetSample]:
        """Build raw text samples from SKO content for continued pre-training.

        Returns:
            List of DatasetSample objects.
        """
        samples: List[DatasetSample] = []
        for sko in self._store.list_all():
            content = sko.raw_content
            if not content or len(content.strip()) < 100:
                continue
            samples.append(
                DatasetSample(
                    instruction="",
                    input="",
                    output=content[:4096],
                    source=sko.source,
                    metadata={"sko_id": sko.id, "type": "text"},
                )
            )
        logger.info("Built %d text samples", len(samples))
        return samples

    def save(
        self,
        samples: List[DatasetSample],
        output_path: Optional[str | Path] = None,
    ) -> Path:
        """Save dataset samples to a JSONL file.

        Args:
            samples: Dataset samples to persist.
            output_path: Destination path (default from config).

        Returns:
            The resolved output Path.

        Raises:
            TrainingError: If writing fails.
        """
        target = Path(output_path) if output_path else Path(self._config.output_dir)
        target = ensure_dir(target) / "dataset.jsonl"

        try:
            with open(target, "w") as f:
                for sample in samples:
                    f.write(json.dumps(sample.to_dict(), default=str) + "\n")
        except OSError as exc:
            raise TrainingError(f"Failed to write dataset to {target}: {exc}") from exc

        logger.info("Saved %d samples to %s", len(samples), target)
        return target