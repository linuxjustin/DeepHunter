"""Provider registry for the Model Router.

Providers self-register.  The registry supports plugin-style discovery
without giant if/else chains.
"""

from __future__ import annotations

from deephunter.router.capabilities import Capability, TaskType, get_capabilities_for_task_str
from deephunter.router.provider import LegacyProviderAdapter, ModelProvider


class ProviderRegistry:
    """Registry of AI providers.

    Providers register themselves by name.  The registry supports
    lookup by name, capability, and task type.
    """

    def __init__(self) -> None:
        self._providers: dict[str, ModelProvider] = {}

    def register(self, provider: ModelProvider) -> None:
        """Register a provider.

        Args:
            provider: A ModelProvider instance.

        Raises:
            ValueError: If a provider with the same name is already registered.
        """
        name = provider.name
        if name in self._providers:
            raise ValueError(f"Provider '{name}' is already registered")
        self._providers[name] = provider

    def deregister(self, name: str) -> None:
        """Remove a provider from the registry.

        Args:
            name: Provider name to remove.  No error if not found.
        """
        self._providers.pop(name, None)

    def get(self, name: str) -> ModelProvider | None:
        """Get a provider by name.

        Args:
            name: Provider name.

        Returns:
            The ModelProvider, or None if not registered.
        """
        return self._providers.get(name)

    def list_providers(self) -> list[ModelProvider]:
        """Return all registered providers."""
        return list(self._providers.values())

    def list_names(self) -> list[str]:
        """Return names of all registered providers."""
        return list(self._providers.keys())

    def find_by_capability(self, capability: str) -> list[ModelProvider]:
        """Find providers whose models support a given capability.

        Args:
            capability: A capability string (e.g. 'reasoning', 'vision').

        Returns:
            List of providers that support the capability.
        """
        return [p for p in self._providers.values() if p.supports_capability(capability)]

    def find_by_task(self, task_type: str) -> list[ModelProvider]:
        """Find providers that support a given task type.

        Translates the task type to required capabilities and finds
        matching providers.

        Args:
            task_type: A task type string (e.g. 'reasoning', 'code_analysis').

        Returns:
            List of providers that support all required capabilities.
        """
        caps = get_capabilities_for_task_str(task_type)
        if not caps:
            return self.list_providers()
        return [
            p for p in self._providers.values()
            if all(p.supports_capability(c) for c in caps)
        ]

    def count(self) -> int:
        """Return the number of registered providers."""
        return len(self._providers)

    def clear(self) -> None:
        """Remove all providers."""
        self._providers.clear()
