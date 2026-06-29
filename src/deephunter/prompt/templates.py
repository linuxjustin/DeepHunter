"""Prompt template management.

Templates are stored separately from code and support future
localization and custom prompt styles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deephunter.prompt.models import PromptStyle, PromptTemplate


# Default built-in templates — stored in code as fallbacks.
# Custom templates can be loaded from a template directory.
_BUILTIN_TEMPLATES: dict[str, PromptTemplate] = {
    "investigation_default": PromptTemplate(
        id="investigation_default",
        name="Investigation Default",
        style=PromptStyle.INVESTIGATION,
        description="Default investigation prompt for security researchers",
        system_template=(
            "You are an expert security researcher conducting a penetration test.\n"
            "Use the following investigation context to guide your analysis.\n"
            "Be thorough, methodical, and precise."
        ),
        user_template=(
            "# Investigation Context\n\n"
            "{% if target_info %}\n## Target Information\n{{ target_info }}\n{% endif %}\n\n"
            "{% if technology_fingerprint %}\n## Technology Fingerprint\n{{ technology_fingerprint }}\n{% endif %}\n\n"
            "{% if observations %}\n## Observations\n{{ observations }}\n{% endif %}\n\n"
            "{% if evidence %}\n## Evidence\n{{ evidence }}\n{% endif %}\n\n"
            "{% if findings %}\n## Findings\n{{ findings }}\n{% endif %}\n\n"
            "{% if investigation_plan %}\n## Investigation Plan\n{{ investigation_plan }}\n{% endif %}\n\n"
            "{% if user_query %}\n## User Query\n{{ user_query }}\n{% endif %}\n\n"
            "{% if constraints %}\n## Constraints\n{{ constraints }}\n{% endif %}\n\n"
            "Based on the above context, provide your analysis and recommendations."
        ),
        developer_template="",
        variables=[
            "target_info", "technology_fingerprint", "observations",
            "evidence", "findings", "investigation_plan",
            "user_query", "constraints",
        ],
    ),
    "reasoning_default": PromptTemplate(
        id="reasoning_default",
        name="Reasoning Default",
        style=PromptStyle.REASONING,
        description="Default prompt for generating reasoning hypotheses",
        system_template=(
            "You are an expert security researcher generating hypotheses about potential vulnerabilities.\n"
            "Analyze the context and propose testable hypotheses."
        ),
        user_template=(
            "# Investigation Context\n\n"
            "{{ context_summary }}\n\n"
            "Generate hypotheses about potential vulnerabilities based on the above context."
        ),
        developer_template="",
        variables=["context_summary"],
    ),
    "planning_default": PromptTemplate(
        id="planning_default",
        name="Planning Default",
        style=PromptStyle.PLANNING,
        description="Default prompt for refining investigation plans",
        system_template=(
            "You are an expert security researcher planning an investigation.\n"
            "Review the investigation context and generated plan, then provide refinements."
        ),
        user_template=(
            "# Investigation Context\n\n{{ context_summary }}\n\n"
            "# Current Plan\n\n{{ investigation_plan }}\n\n"
            "Review the plan above and suggest refinements or additional steps."
        ),
        developer_template="",
        variables=["context_summary", "investigation_plan"],
    ),
    "code_review_default": PromptTemplate(
        id="code_review_default",
        name="Code Review Default",
        style=PromptStyle.CODE_REVIEW,
        description="Default prompt for security code review",
        system_template=(
            "You are an expert security code reviewer.\n"
            "Analyze the provided context for security vulnerabilities and anti-patterns."
        ),
        user_template=(
            "# Code Review Context\n\n{{ context_summary }}\n\n"
            "Review the above context for security issues."
        ),
        developer_template="",
        variables=["context_summary"],
    ),
    "reporting_default": PromptTemplate(
        id="reporting_default",
        name="Reporting Default",
        style=PromptStyle.REPORTING,
        description="Default prompt for generating security reports",
        system_template=(
            "You are an expert security report writer.\n"
            "Generate a professional security assessment report based on the investigation context."
        ),
        user_template=(
            "# Investigation Context\n\n{{ context_summary }}\n\n"
            "Generate a comprehensive security assessment report."
        ),
        developer_template="",
        variables=["context_summary"],
    ),
}


class TemplateRegistry:
    """Registry for prompt templates.

    Built-in templates are always available.  Custom templates can be
    registered at runtime or loaded from a template directory.
    """

    def __init__(self, template_directory: str | Path | None = None) -> None:
        self._templates: dict[str, PromptTemplate] = dict(_BUILTIN_TEMPLATES)
        if template_directory:
            self._load_from_directory(template_directory)

    def get(self, template_id: str) -> PromptTemplate | None:
        return self._templates.get(template_id)

    def get_by_style(self, style: PromptStyle) -> list[PromptTemplate]:
        return [t for t in self._templates.values() if t.style == style]

    def register(self, template: PromptTemplate) -> None:
        self._templates[template.id] = template

    def deregister(self, template_id: str) -> None:
        self._templates.pop(template_id, None)

    def list_templates(self) -> list[PromptTemplate]:
        return list(self._templates.values())

    def _load_from_directory(self, directory: str | Path) -> None:
        directory = Path(directory)
        if not directory.is_dir():
            return
        for path in directory.glob("*.json"):
            try:
                with open(path) as f:
                    data: dict[str, Any] = json.load(f)
                template = PromptTemplate(**data)
                self._templates[template.id] = template
            except (json.JSONDecodeError, Exception):
                import logging

                logging.getLogger(__name__).warning(
                    "Failed to load template from %s", path
                )
