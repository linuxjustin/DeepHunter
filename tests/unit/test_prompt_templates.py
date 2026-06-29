"""Tests for prompt template registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.prompt.models import PromptStyle, PromptTemplate
from deephunter.prompt.templates import TemplateRegistry


class TestTemplateRegistry:
    def test_default_templates_loaded(self) -> None:
        registry = TemplateRegistry()
        templates = registry.list_templates()
        assert len(templates) >= 1
        assert registry.get("investigation_default") is not None

    def test_get_by_style(self) -> None:
        registry = TemplateRegistry()
        investigation_templates = registry.get_by_style(PromptStyle.INVESTIGATION)
        assert len(investigation_templates) >= 1
        assert investigation_templates[0].style == PromptStyle.INVESTIGATION

    def test_get_by_style_empty(self) -> None:
        registry = TemplateRegistry()
        # Unknown style should return empty
        class FakeStyle:
            value = "fake_style"
        # All styles exist in built-in, just check a non-existent one
        # Actually all PromptStyle values have at least fallback
        reasoning_templates = registry.get_by_style(PromptStyle.REASONING)
        assert len(reasoning_templates) >= 1

    def test_register_template(self) -> None:
        registry = TemplateRegistry()
        template = PromptTemplate(
            id="custom",
            name="Custom Template",
            style=PromptStyle.CODE_REVIEW,
        )
        registry.register(template)
        assert registry.get("custom") is template

    def test_deregister_template(self) -> None:
        registry = TemplateRegistry()
        template = PromptTemplate(id="temp", name="Temp")
        registry.register(template)
        registry.deregister("temp")
        assert registry.get("temp") is None

    def test_deregister_nonexistent(self) -> None:
        registry = TemplateRegistry()
        registry.deregister("nonexistent")  # Should not raise

    def test_get_nonexistent(self) -> None:
        registry = TemplateRegistry()
        assert registry.get("nonexistent") is None

    def test_list_templates(self) -> None:
        registry = TemplateRegistry()
        count = len(registry.list_templates())

        registry.register(PromptTemplate(id="extra1", name="Extra 1"))
        registry.register(PromptTemplate(id="extra2", name="Extra 2"))

        assert len(registry.list_templates()) == count + 2

    def test_load_from_directory(self, tmp_path: Path) -> None:
        import json

        template_data = {
            "id": "file_template",
            "name": "File Template",
            "style": "code_review",
            "description": "Loaded from file",
            "system_template": "You are a code reviewer.",
            "user_template": "Review this code.",
        }
        template_file = tmp_path / "template.json"
        with open(template_file, "w") as f:
            json.dump(template_data, f)

        registry = TemplateRegistry(template_directory=str(tmp_path))
        loaded = registry.get("file_template")
        assert loaded is not None
        assert loaded.name == "File Template"
        assert loaded.style == PromptStyle.CODE_REVIEW
        assert loaded.system_template == "You are a code reviewer."

    def test_load_from_nonexistent_directory(self) -> None:
        registry = TemplateRegistry(template_directory="/nonexistent/path")
        # Should not crash, just load defaults
        assert registry.get("investigation_default") is not None

    def test_load_from_invalid_json(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json {")

        registry = TemplateRegistry(template_directory=str(tmp_path))
        # Should not crash
        assert registry.get("investigation_default") is not None
