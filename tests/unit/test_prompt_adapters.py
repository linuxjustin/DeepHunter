"""Tests for prompt model adapters."""

from __future__ import annotations

import pytest

from deephunter.prompt.adapters import IdentityAdapter, ModelAdapter
from deephunter.prompt.models import Prompt, PromptMessageRole


class TestIdentityAdapter:
    def test_adapt_returns_same_prompt(self) -> None:
        adapter = IdentityAdapter()
        prompt = Prompt(investigation_id="inv-1")
        prompt.add_message(PromptMessageRole.SYSTEM, "System")

        result = adapter.adapt(prompt)
        assert result.id == prompt.id
        assert len(result.messages) == 1
        assert result.messages[0].content == "System"

    def test_estimate_tokens(self) -> None:
        adapter = IdentityAdapter()
        tokens = adapter.estimate_tokens("hello world test")
        # 3 words / 0.75 = 4
        assert tokens == 4

    def test_estimate_tokens_empty(self) -> None:
        adapter = IdentityAdapter()
        tokens = adapter.estimate_tokens("")
        assert tokens == 1

    def test_name(self) -> None:
        adapter = IdentityAdapter()
        assert adapter.name == "identity"


class TestModelAdapterABC:
    def test_cannot_instantiate_abc(self) -> None:
        with pytest.raises(TypeError):
            ModelAdapter()  # type: ignore[abstract]
