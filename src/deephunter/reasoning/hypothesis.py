"""Hypothesis generation engine.

Produces ranked investigation hypotheses based on retrieved SKOs,
bug class prevalence, technology stacks, and framework-aware reasoning.

Uses an LLM provider when available, with template-based fallback
for offline operation.
"""

from __future__ import annotations

from deephunter.core.config import ReasoningConfig
from deephunter.core.exceptions import ReasoningError
from deephunter.core.types import BugClass, Confidence, Technology
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.llm.base import LLMProvider
from deephunter.rag.retriever import Retriever
from deephunter.reasoning.models import Hypothesis, HypothesisPriority
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


HYPOTHESIS_PROMPT_TEMPLATE = """You are a senior security researcher generating investigation hypotheses.

Given the following security knowledge context and bug class distribution,
generate ranked investigation hypotheses for the target: {context}

Relevant bug classes found in knowledge base:
{bug_classes}

Relevant technologies:
{technologies}

Related knowledge snippets:
{knowledge_snippets}

For each hypothesis, provide:
1. Title: A concise title
2. Description: What vulnerability to investigate
3. Bug Class: The primary bug class
4. Rationale: Why this is worth investigating
5. Testing Ideas: 1-2 specific testing approaches
6. Priority: critical/high/medium/low

Respond with a JSON array of hypotheses."""


class HypothesisGenerator:
    """Generates ranked investigation hypotheses from knowledge.

    Uses the LLM provider for intelligent hypothesis generation when
    available, with a deterministic template-based fallback for offline mode.
    """

    # Template-based fallback rules
    FALLBACK_RULES: dict[BugClass, dict[str, str]] = {
        BugClass.AUTH_BYPASS: {
            "title": "Authentication bypass in {tech} application",
            "description": (
                "The application uses {tech} for authentication, "
                "which may contain common bypass patterns found in knowledge base."
            ),
            "rationale": (
                "Authentication logic is frequently discovered to have "
                "implementation flaws in {tech}-based applications."
            ),
            "test": "Test for missing or weak token validation in {tech} endpoints.",
        },
        BugClass.SQL_INJECTION: {
            "title": "SQL injection in {tech} parameters",
            "description": (
                "The application uses {tech} and may have SQL injection "
                "vulnerabilities in user-supplied parameters."
            ),
            "rationale": (
                "SQL injection remains prevalent in {tech} applications "
                "when input validation is insufficient."
            ),
            "test": "Test all user-supplied parameters for SQL injection using common payloads.",
        },
        BugClass.XSS: {
            "title": "Cross-site scripting in {tech} templates",
            "description": (
                "The application uses {tech} which may have template injection "
                "or reflection XSS vulnerabilities."
            ),
            "rationale": (
                "XSS is consistently the most reported vulnerability in "
                "web applications across all technology stacks."
            ),
            "test": "Test all input fields and URL parameters for XSS reflection.",
        },
        BugClass.IDOR: {
            "title": "Insecure direct object reference in {tech} API",
            "description": (
                "The {tech} application may expose direct object references "
                "in its API endpoints."
            ),
            "rationale": (
                "IDOR vulnerabilities are common in {tech} REST APIs "
                "when authorization checks are missing on object-level operations."
            ),
            "test": "Enumerate object IDs in API endpoints and verify authorization.",
        },
        BugClass.SSRF: {
            "title": "Server-side request forgery in {tech} application",
            "description": (
                "The {tech} application may be vulnerable to SSRF if it "
                "fetches remote resources based on user input."
            ),
            "rationale": (
                "SSRF is a critical vulnerability in {tech} applications "
                "that process URLs or fetch external content."
            ),
            "test": "Identify features that fetch URLs and test with internal address schemes.",
        },
        BugClass.RACE_CONDITION: {
            "title": "Race condition in {tech} concurrent operations",
            "description": (
                "The {tech} application may have race conditions in "
                "concurrent state-modifying operations."
            ),
            "rationale": (
                "Race conditions are frequently overlooked in {tech} "
                "applications with async processing."
            ),
            "test": "Send concurrent requests to state-modifying endpoints.",
        },
        BugClass.DESERIALIZATION: {
            "title": "Insecure deserialization in {tech} application",
            "description": (
                "The {tech} application may be vulnerable to deserialization "
                "attacks if it processes serialized objects."
            ),
            "rationale": (
                "Insecure deserialization is a critical class of vulnerability "
                "in {tech} applications handling user-supplied data."
            ),
            "test": "Identify endpoints that accept serialized formats and test with malformed payloads.",
        },
    }

    def __init__(
        self,
        store: KnowledgeStore,
        retriever: Retriever,
        config: ReasoningConfig,
        llm_provider: LLMProvider | None = None,
    ) -> None:
        self._store = store
        self._retriever = retriever
        self._config = config
        self._llm_provider = llm_provider

    def generate(
        self,
        context: str,
        skos: list[SecurityKnowledgeObject] | None = None,
    ) -> list[Hypothesis]:
        """Generate hypotheses based on a context query and optional SKOs.

        Uses the LLM provider when available, falls back to template-based
        generation for offline operation.

        Args:
            context: Description of the target or research focus.
            skos: Optional pre-retrieved SKOs (if not provided, uses RAG).

        Returns:
            Ranked list of Hypothesis objects.

        Raises:
            ReasoningError: If hypothesis generation fails.
        """
        try:
            if skos is None:
                scored = self._retriever.query(context)
                skos = [s for s, _ in scored]
        except Exception as exc:
            raise ReasoningError(f"Failed to retrieve context SKOs: {exc}") from exc

        if self._llm_provider is not None:
            try:
                return self._generate_with_llm(context, skos)
            except Exception as exc:
                logger.warning("LLM hypothesis generation failed, using fallback: %s", exc)

        return self._generate_fallback(context, skos)

    def _generate_with_llm(
        self,
        context: str,
        skos: list[SecurityKnowledgeObject],
    ) -> list[Hypothesis]:
        """Generate hypotheses using the LLM provider."""
        bug_classes = set()
        technologies = set()
        snippets: list[str] = []

        for sko in skos:
            bug_classes.update(sko.bug_classes)
            technologies.update(sko.technology)
            if sko.raw_content:
                snippets.append(sko.raw_content[:300])

        bc_str = ", ".join(b.value for b in sorted(bug_classes, key=lambda x: x.value))
        tech_str = ", ".join(t.value for t in sorted(technologies, key=lambda x: x.value))
        snippet_str = "\n".join(f"- {s}" for s in snippets[:5])

        prompt = HYPOTHESIS_PROMPT_TEMPLATE.format(
            context=context,
            bug_classes=bc_str or "none detected",
            technologies=tech_str or "unknown",
            knowledge_snippets=snippet_str or "no relevant knowledge found",
        )

        response = self._llm_provider.generate(
            prompt=prompt,
            system_prompt="You are a senior security researcher. Output only valid JSON.",
            temperature=0.3,
        )

        try:
            import json
            data = json.loads(response.content)
            return self._parse_llm_hypotheses(data, skos)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Failed to parse LLM hypothesis output: %s", exc)
            raise ReasoningError(f"LLM output was not valid JSON: {exc}") from exc

    def _parse_llm_hypotheses(
        self,
        data: list[dict],
        skos: list[SecurityKnowledgeObject],
    ) -> list[Hypothesis]:
        """Parse structured JSON output from LLM into Hypothesis objects."""
        hypotheses: list[Hypothesis] = []
        for item in data[: self._config.hypothesis_limit]:
            bc_values = item.get("bug_class", "")
            if isinstance(bc_values, str):
                bc_values = [bc_values]

            bug_classes: list[BugClass] = []
            for val in bc_values:
                try:
                    bug_classes.append(BugClass(val.lower().replace(" ", "_")))
                except ValueError:
                    pass

            priority_str = item.get("priority", "medium").lower()
            try:
                priority = HypothesisPriority(priority_str)
            except ValueError:
                priority = HypothesisPriority.MEDIUM

            hyp = Hypothesis(
                title=item.get("title", "Untitled hypothesis"),
                description=item.get("description", ""),
                bug_classes=bug_classes,
                priority=priority,
                confidence=0.5,
                rationale=item.get("rationale", ""),
                testing_ideas=item.get("testing_ideas", []),
                related_skos=[s.id for s in skos[:3]],
            )
            hypotheses.append(hyp)

        return hypotheses

    def _generate_fallback(
        self,
        context: str,
        skos: list[SecurityKnowledgeObject],
    ) -> list[Hypothesis]:
        """Generate hypotheses using template-based fallback."""
        bug_class_counts: dict[BugClass, int] = {}
        tech_set: set[Technology] = set()

        for sko in skos:
            for bc in sko.bug_classes:
                bug_class_counts[bc] = bug_class_counts.get(bc, 0) + 1
            tech_set.update(sko.technology)

        all_skos = self._store.list_all()
        for sko in all_skos:
            for bc in sko.bug_classes:
                if bc not in bug_class_counts:
                    bug_class_counts[bc] = 1

        tech_list = list(tech_set) if tech_set else [Technology.OTHER]
        tech_strs = [t.value for t in tech_list]

        _CONFIDENCE_MAP = {
            Confidence.HIGH: 0.8,
            Confidence.MEDIUM: 0.5,
            Confidence.LOW: 0.2,
            Confidence.UNKNOWN: 0.0,
        }

        hypotheses: list[Hypothesis] = []
        for bc, count in bug_class_counts.items():
            if count <= 0:
                continue
            rule = self.FALLBACK_RULES.get(bc)
            if rule is None:
                continue

            tech_str = tech_list[0].value if tech_list else "the"
            conf_enum = self._confidence_from_count(count)

            hyp = Hypothesis(
                title=rule["title"].format(tech=tech_str),
                description=rule["description"].format(tech=tech_str),
                bug_classes=[bc],
                technologies=tech_strs[:3],
                priority=self._priority_from_confidence(conf_enum),
                confidence=_CONFIDENCE_MAP.get(conf_enum, 0.0),
                rationale=rule["rationale"].format(tech=tech_str),
                testing_ideas=[rule["test"].format(tech=tech_str)],
                related_skos=[s.id for s in skos if bc in s.bug_classes][:5],
            )
            hypotheses.append(hyp)

        _PRIORITY_RANK = {
            HypothesisPriority.CRITICAL: 0,
            HypothesisPriority.HIGH: 1,
            HypothesisPriority.MEDIUM: 2,
            HypothesisPriority.LOW: 3,
            HypothesisPriority.INFO: 4,
        }
        hypotheses.sort(key=lambda h: (_PRIORITY_RANK.get(h.priority, 99), -h.confidence))
        limit = self._config.hypothesis_limit
        hypotheses = hypotheses[:limit]

        logger.info("Generated %d fallback hypotheses", len(hypotheses))
        return hypotheses

    @staticmethod
    def _confidence_from_count(count: int) -> Confidence:
        if count >= 5:
            return Confidence.HIGH
        if count >= 3:
            return Confidence.MEDIUM
        return Confidence.LOW

    @staticmethod
    def _priority_from_confidence(conf: Confidence) -> HypothesisPriority:
        mapping = {
            Confidence.HIGH: HypothesisPriority.CRITICAL,
            Confidence.MEDIUM: HypothesisPriority.HIGH,
            Confidence.LOW: HypothesisPriority.MEDIUM,
            Confidence.UNKNOWN: HypothesisPriority.LOW,
        }
        return mapping.get(conf, HypothesisPriority.MEDIUM)
