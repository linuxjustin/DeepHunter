"""Security Knowledge Object (SKO) generation from JavaScript Intelligence.

Converts JS analysis observations into structured SKOs for persistence
and integration with the Knowledge Store, Planner, and Reasoning Engine.
"""

from __future__ import annotations

from deephunter.core.types import (
    BugClass,
    DocumentType,
    SourceType,
    Technology,
)
from deephunter.js_intel.models import JSAnalysisResult
from deephunter.knowledge.models import SecurityKnowledgeObject


class JSSKOGenerator:
    """Generates SecurityKnowledgeObjects from JavaScript analysis results.

    Usage::

        generator = JSSKOGenerator()
        skos = generator.generate(result)
    """

    def generate(self, result: JSAnalysisResult) -> list[SecurityKnowledgeObject]:
        """Generate SKOs from a JS analysis result.

        Produces one or more SKOs depending on the findings:
        - A main SKO for the JS file analysis
        - Additional SKOs for significant observations (secrets, auth)

        Args:
            result: JSAnalysisResult from the parser/engine.

        Returns:
            List of SecurityKnowledgeObject instances.
        """
        skos: list[SecurityKnowledgeObject] = []

        # ── Main JS analysis SKO ────────────────────────────────────
        main_sko = self._build_main_sko(result)
        skos.append(main_sko)

        # ── Secrets SKO (if any found) ──────────────────────────────
        for secret in result.secret_observations:
            skos.append(self._build_secret_sko(result, secret))

        return skos

    @staticmethod
    def _build_main_sko(result: JSAnalysisResult) -> SecurityKnowledgeObject:
        title = f"JavaScript Analysis: {result.source_url or 'unknown source'}"
        description_parts: list[str] = []
        if result.detected_frameworks:
            description_parts.append(f"Frameworks detected: {', '.join(result.detected_frameworks)}")
        if result.modules:
            description_parts.append(f"Modules imported: {len(result.modules)}")
        if result.api_endpoints:
            description_parts.append(f"API endpoints referenced: {len(result.api_endpoints)}")
        if result.auth_observations:
            description_parts.append(f"Auth observations: {len(result.auth_observations)}")
        if result.routes:
            description_parts.append(f"Client routes defined: {len(result.routes)}")

        summary = "; ".join(description_parts) if description_parts else "No significant observations"

        bug_classes: list[BugClass] = []
        if result.secret_observations:
            bug_classes.append(BugClass.INFO_DISCLOSURE)

        return SecurityKnowledgeObject(
            title=title,
            summary=summary,
            description="\n".join(description_parts) if description_parts else "No significant observations",
            source=result.source_url or "unknown",
            source_type=SourceType.OTHER,
            document_type=DocumentType.CODE,
            technology=[Technology(name=fw) for fw in result.detected_frameworks],
            bug_classes=bug_classes,
            tags=["javascript", "analysis"] + result.detected_frameworks + result.build_tool_hints,
            metadata=[
                {"key": "js_analysis_id", "value": result.id},
                {"key": "content_hash", "value": result.content_hash},
                {"key": "content_size", "value": str(result.content_size)},
                {"key": "module_count", "value": str(len(result.modules))},
                {"key": "endpoint_count", "value": str(len(result.api_endpoints))},
                {"key": "auth_observations_count", "value": str(len(result.auth_observations))},
                {"key": "is_bundle", "value": str(result.is_bundle)},
                {"key": "has_source_map", "value": str(result.has_source_map)},
            ],
        )

    @staticmethod
    def _build_secret_sko(result: JSAnalysisResult, secret: Any) -> SecurityKnowledgeObject:
        return SecurityKnowledgeObject(
            title=f"Potential {secret.secret_type} in {result.source_url or 'unknown'}",
            summary=f"Found {secret.secret_type} at line {secret.line_number}",
            description=f"Secret type: {secret.secret_type}\n"
                        f"Preview: {secret.value_preview}\n"
                        f"Entropy: {secret.entropy:.2f}\n"
                        f"Source: {result.source_url}",
            source=result.source_url or "unknown",
            source_type=SourceType.OTHER,
            document_type=DocumentType.CODE,
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["javascript", "secret", secret.secret_type],
            metadata=[
                {"key": "js_analysis_id", "value": result.id},
                {"key": "line_number", "value": str(secret.line_number)},
                {"key": "secret_type", "value": secret.secret_type},
            ],
        )
