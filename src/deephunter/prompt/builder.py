"""Prompt Builder — transforms structured Context into model-ready prompts.

Independent of any LLM.  No AI, no embeddings, no RAG.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deephunter.context.models import (
    Context,
    ContextImportance,
    ContextSection,
    ContextSourceType,
)
from deephunter.prompt.adapters import IdentityAdapter, ModelAdapter
from deephunter.prompt.events import (
    PromptAdapterAppliedEvent,
    PromptFormatAppliedEvent,
    PromptGeneratedEvent,
    PromptTemplateLoadedEvent,
    PromptTemplateNotFoundEvent,
    PromptEventBus,
)
from deephunter.prompt.formats import PromptFormatter, get_formatter
from deephunter.prompt.models import (
    Prompt,
    PromptFormat,
    PromptMessage,
    PromptMessageRole,
    PromptMetadata,
    PromptReference,
    PromptStatistics,
    PromptStyle,
    PromptTemplate,
)
from deephunter.prompt.templates import TemplateRegistry


class PromptBuilder:
    """Facade for building model-ready prompts from structured Context.

    Usage::

        builder = PromptBuilder()
        prompt = builder.build(context, style=PromptStyle.INVESTIGATION)
        system, user = prompt.to_system_user()
    """

    def __init__(
        self,
        template_registry: TemplateRegistry | None = None,
        event_bus: PromptEventBus | None = None,
    ) -> None:
        self._template_registry = template_registry or TemplateRegistry()
        self._event_bus = event_bus or PromptEventBus()
        self._adapters: dict[str, ModelAdapter] = {}
        self._default_adapter: ModelAdapter = IdentityAdapter()

    def build(
        self,
        context: Context,
        style: PromptStyle = PromptStyle.INVESTIGATION,
        template_name: str = "",
        fmt: PromptFormat | str = PromptFormat.MARKDOWN,
        adapter_name: str = "",
    ) -> Prompt:
        """Build a Prompt from a Context object.

        Args:
            context: The structured context to build from.
            style: The prompt style to use.
            template_name: Optional specific template ID.  If empty, the
                first template matching the requested style is used.
            fmt: Output format (markdown, plain_text, json, structured).
            adapter_name: Optional model adapter name.

        Returns:
            A fully populated Prompt object.
        """
        prompt = Prompt(
            context_id=context.id,
            investigation_id=context.investigation_id,
        )

        template = self._resolve_template(style, template_name)
        if template is None:
            prompt.warnings.append(f"No template found for style {style.value}")
            template = self._fallback_template(style)

        if template:
            prompt.metadata.template_name = template.name
            self._event_bus.emit(PromptTemplateLoadedEvent(
                investigation_id=context.investigation_id,
                context_id=context.id,
                template_name=template.name,
                template_style=style.value,
            ))

        prompt.metadata.style = style
        prompt.metadata.format = fmt.value if isinstance(fmt, PromptFormat) else fmt

        # Build messages from context sections
        self._build_system_message(prompt, template, context)
        self._build_user_message(prompt, template, context)
        self._build_developer_message(prompt, template)

        # Add references from context
        for ref in context.references:
            prompt.references.append(PromptReference(
                reference_type=ref.reference_type,
                identifier=ref.identifier,
                title=ref.title,
                url=ref.url,
                description=ref.description,
            ))

        # Apply formatting
        self._apply_format(prompt, fmt)

        # Apply adapter if specified
        if adapter_name:
            prompt = self._apply_adapter(prompt, adapter_name)

        # Recalculate statistics
        prompt.recalculate()

        # Add warnings from context
        prompt.warnings.extend(context.warnings)

        # Emit generated event
        self._event_bus.emit(PromptGeneratedEvent(
            investigation_id=context.investigation_id,
            context_id=context.id,
            prompt_id=prompt.id,
            style=style.value,
            message_count=len(prompt.messages),
            estimated_tokens=prompt.statistics.estimated_tokens,
        ))

        return prompt

    def _resolve_template(self, style: PromptStyle, template_name: str) -> PromptTemplate | None:
        if template_name:
            template = self._template_registry.get(template_name)
            if template is None:
                self._event_bus.emit(PromptTemplateNotFoundEvent(
                    template_name=template_name,
                ))
            return template
        templates = self._template_registry.get_by_style(style)
        return templates[0] if templates else None

    def _fallback_template(self, style: PromptStyle) -> PromptTemplate:
        return PromptTemplate(
            id=f"{style.value}_fallback",
            name=f"{style.value.title()} Fallback",
            style=style,
            system_template="You are an expert security researcher. Use the context below for your analysis.",
            user_template="{{ context_summary }}",
            variables=["context_summary"],
        )

    def _build_system_message(self, prompt: Prompt, template: PromptTemplate | None, context: Context) -> None:
        content = self._render_template(template.system_template if template else "", context) if template else ""
        if not content:
            content = "You are an expert security researcher. Use the context below for your analysis."
        prompt.add_message(PromptMessageRole.SYSTEM, content)

    def _build_user_message(self, prompt: Prompt, template: PromptTemplate | None, context: Context) -> None:
        if template and template.user_template:
            content = self._render_template(template.user_template, context)
        else:
            content = self._build_default_user_content(context)
        if not content:
            content = "Analyze the following investigation context."
        prompt.add_message(PromptMessageRole.USER, content)

    def _build_developer_message(self, prompt: Prompt, template: PromptTemplate | None) -> None:
        if template and template.developer_template:
            prompt.add_message(
                PromptMessageRole.DEVELOPER,
                template.developer_template,
            )

    def _build_default_user_content(self, context: Context) -> str:
        parts: list[str] = ["# Investigation Context\n"]
        for section in context.sections:
            if not section.blocks:
                continue
            parts.append(f"## {section.name}")
            if section.description:
                parts.append(f"_{section.description}_\n")
            for block in section.blocks:
                parts.append(block.content.strip())
                if block.summary:
                    parts.append(f"*Summary: {block.summary}*")
                parts.append("")
        return "\n".join(parts).strip()

    def _render_template(self, template_str: str, context: Context) -> str:
        """Simple variable substitution in templates.

        Uses a basic {{ variable }} syntax.  Supports:
        - Section names as variables (spaces/underscores normalized)
        - ``context_summary`` for the full context dump
        - Nested section data
        """
        result = template_str

        # Full context summary
        if "{{ context_summary }}" in result:
            summary = self._build_default_user_content(context)
            result = result.replace("{{ context_summary }}", summary)

        # Per-section variables
        for section in context.sections:
            var_name = section.name.lower().replace(" ", "_").replace("-", "_")
            placeholder = "{{ " + var_name + " }}"
            if placeholder in result:
                section_content = "\n".join(b.content for b in section.blocks)
                result = result.replace(placeholder, section_content)

        # Individual variable references
        for section in context.sections:
            for block in section.blocks:
                for key, value in block.metadata.items():
                    placeholder = "{{ " + key + " }}"
                    if placeholder in result:
                        result = result.replace(placeholder, str(value))

        return result

    def _apply_format(self, prompt: Prompt, fmt: PromptFormat | str) -> None:
        try:
            formatter = get_formatter(fmt)
            # We store the formatted string representation in metadata
            prompt.metadata.format = fmt.value if isinstance(fmt, PromptFormat) else fmt
            self._event_bus.emit(PromptFormatAppliedEvent(
                investigation_id=prompt.investigation_id,
                context_id=prompt.context_id,
                prompt_id=prompt.id,
                format_name=prompt.metadata.format,
            ))
        except ValueError:
            prompt.warnings.append(f"Unknown format: {fmt}")

    def _apply_adapter(self, prompt: Prompt, adapter_name: str) -> Prompt:
        adapter = self._adapters.get(adapter_name)
        if adapter is None:
            prompt.warnings.append(f"Unknown adapter: {adapter_name}. Using identity.")
            adapter = self._default_adapter
        prompt.metadata.model_adapter = adapter.name
        adapted = adapter.adapt(prompt)
        self._event_bus.emit(PromptAdapterAppliedEvent(
            investigation_id=adapted.investigation_id,
            context_id=adapted.context_id,
            prompt_id=adapted.id,
            adapter_name=adapter.name,
        ))
        return adapted

    def register_adapter(self, name: str, adapter: ModelAdapter) -> None:
        self._adapters[name] = adapter

    def save_prompt(self, prompt: Prompt, path: str | Path) -> Path:
        """Persist a Prompt to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = prompt.model_dump(mode="json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def load_prompt(self, path: str | Path) -> Prompt:
        """Load a Prompt from a JSON file."""
        path = Path(path)
        with open(path) as f:
            data: dict[str, Any] = json.load(f)
        return Prompt.from_dict(data)

    @property
    def event_bus(self) -> PromptEventBus:
        return self._event_bus

    @property
    def template_registry(self) -> TemplateRegistry:
        return self._template_registry
