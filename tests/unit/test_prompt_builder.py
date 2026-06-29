"""Integration tests for the Prompt Builder."""

from __future__ import annotations

from pathlib import Path

from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextImportance,
    ContextReference,
    ContextSection,
    ContextSourceType,
)
from deephunter.prompt.builder import PromptBuilder
from deephunter.prompt.events import (
    PromptEventBus,
    PromptGeneratedEvent,
    PromptTemplateLoadedEvent,
)
from deephunter.prompt.models import (
    Prompt,
    PromptFormat,
    PromptMessageRole,
    PromptStyle,
)


def _make_sample_context() -> Context:
    ctx = Context(investigation_id="inv-test")
    # Target section
    target = ContextSection(name="Target Information", description="Investigation target")
    target.add_block(ContextBlock(
        source_type=ContextSourceType.REASONING_SESSION,
        importance=ContextImportance.CRITICAL,
        priority=1.0,
        content="Target: https://example.com\nInvestigation ID: inv-test",
        summary="Main target",
    ))
    ctx.add_section(target)

    # Technology section
    tech = ContextSection(name="Technology Fingerprint", description="Detected technologies")
    tech.add_block(ContextBlock(
        source_type=ContextSourceType.TECHNOLOGY_FINGERPRINT,
        importance=ContextImportance.HIGH,
        priority=0.9,
        content="Technologies: Django, PostgreSQL\nFrameworks: Django REST Framework",
        summary="Web framework detected",
    ))
    ctx.add_section(tech)

    # Observations
    obs = ContextSection(name="Observations", description="Recorded observations")
    obs.add_block(ContextBlock(
        source_type=ContextSourceType.REASONING_SESSION,
        importance=ContextImportance.MEDIUM,
        priority=0.6,
        content="Type: ENDPOINT\nDescription: Login endpoint at /api/auth/login",
        summary="Login endpoint",
    ))
    ctx.add_section(obs)

    # References
    ctx.references.append(ContextReference(
        reference_type="cve",
        identifier="CVE-2024-1234",
        title="Example CVE",
        url="https://example.com/cve",
    ))

    ctx.warnings.append("Sample warning")
    ctx.recalculate()
    return ctx


class TestPromptBuilder:
    def test_build_minimal(self) -> None:
        builder = PromptBuilder()
        ctx = Context()
        prompt = builder.build(ctx)

        assert prompt.id.startswith("prompt-")
        assert len(prompt.messages) >= 2  # system + user
        assert prompt.statistics.total_messages >= 2

    def test_build_with_context(self) -> None:
        builder = PromptBuilder()
        ctx = _make_sample_context()
        prompt = builder.build(ctx)

        assert prompt.context_id == ctx.id
        assert prompt.investigation_id == "inv-test"
        assert len(prompt.messages) >= 2

        system, user = prompt.to_system_user()
        assert "expert security researcher" in system.lower()
        assert len(user) > 0

    def test_build_with_style(self) -> None:
        builder = PromptBuilder()
        ctx = Context()
        prompt = builder.build(ctx, style=PromptStyle.REASONING)
        assert prompt.metadata.style == PromptStyle.REASONING

    def test_build_with_format(self) -> None:
        builder = PromptBuilder()
        ctx = Context()
        prompt = builder.build(ctx, fmt=PromptFormat.JSON)
        assert prompt.metadata.format == "json"

    def test_build_with_unknown_adapter(self) -> None:
        builder = PromptBuilder()
        ctx = Context()
        prompt = builder.build(ctx, adapter_name="nonexistent")
        assert "Unknown adapter" in prompt.warnings[0]

    def test_build_emits_event(self) -> None:
        bus = PromptEventBus()
        events: list[PromptGeneratedEvent] = []

        bus.subscribe(PromptGeneratedEvent, lambda e: events.append(e))
        builder = PromptBuilder(event_bus=bus)
        ctx = Context()
        builder.build(ctx)

        assert len(events) >= 1
        assert events[0].style == "investigation"

    def test_build_all_styles(self) -> None:
        builder = PromptBuilder()
        ctx = _make_sample_context()

        for style in PromptStyle:
            prompt = builder.build(ctx, style=style)
            assert prompt.metadata.style == style
            assert len(prompt.messages) >= 2

    def test_build_references_included(self) -> None:
        builder = PromptBuilder()
        ctx = _make_sample_context()
        prompt = builder.build(ctx)

        assert len(prompt.references) == 1
        assert prompt.references[0].identifier == "CVE-2024-1234"

    def test_build_warnings_included(self) -> None:
        builder = PromptBuilder()
        ctx = _make_sample_context()
        prompt = builder.build(ctx)

        assert "Sample warning" in prompt.warnings

    def test_build_statistics(self) -> None:
        builder = PromptBuilder()
        ctx = _make_sample_context()
        prompt = builder.build(ctx)

        assert prompt.statistics.total_messages > 0
        assert prompt.statistics.total_characters > 0
        assert prompt.statistics.estimated_tokens > 0
        assert "system" in prompt.statistics.characters_by_role
        assert "user" in prompt.statistics.characters_by_role

    def test_to_system_user(self) -> None:
        builder = PromptBuilder()
        ctx = Context()
        prompt = builder.build(ctx)

        system, user = prompt.to_system_user()
        assert len(system) > 0
        assert len(user) > 0

    def test_save_and_load_prompt(self, tmp_path: Path) -> None:
        builder = PromptBuilder()
        ctx = _make_sample_context()
        prompt = builder.build(ctx)

        path = tmp_path / "prompt.json"
        saved = builder.save_prompt(prompt, str(path))
        assert saved.exists()

        loaded = builder.load_prompt(str(path))
        assert loaded.id == prompt.id
        assert loaded.investigation_id == prompt.investigation_id
        assert len(loaded.messages) == len(prompt.messages)

    def test_template_loaded_event(self) -> None:
        bus = PromptEventBus()
        events: list[PromptTemplateLoadedEvent] = []

        bus.subscribe(PromptTemplateLoadedEvent, lambda e: events.append(e))
        builder = PromptBuilder(event_bus=bus)
        ctx = Context()
        builder.build(ctx)

        assert len(events) >= 1

    def test_build_with_custom_template_name(self) -> None:
        builder = PromptBuilder()
        ctx = Context()

        from deephunter.prompt.models import PromptTemplate
        builder.template_registry.register(PromptTemplate(
            id="custom_template",
            name="Custom",
            style=PromptStyle.INVESTIGATION,
            system_template="Custom system prompt",
            user_template="Custom user prompt with {{ context_summary }}",
        ))

        prompt = builder.build(ctx, template_name="custom_template")
        assert prompt.metadata.template_name == "Custom"
        system, user = prompt.to_system_user()
        assert "Custom system prompt" in system

    def test_build_with_nonexistent_template(self) -> None:
        builder = PromptBuilder()
        ctx = Context()

        prompt = builder.build(ctx, template_name="does_not_exist")
        assert any("template" in w.lower() for w in prompt.warnings)
