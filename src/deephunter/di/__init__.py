"""Dependency injection configuration for DeepHunter.

Provides BccdProvider and autoparams decorator for wiring up
services with dependency injection.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class BccdProvider:
    """Provider for BBCD (DeepHunter) service dependencies.

    This is a simple provider that manages singleton and factory
    instances for the DeepHunter platform.
    """

    _instances: dict[type, Any] = {}
    _factories: dict[type, Callable[[], Any]] = {}

    @classmethod
    def clear(cls) -> None:
        """Clear all registered instances and factories."""
        cls._instances.clear()
        cls._factories.clear()

    @classmethod
    def register_singleton(cls, interface: type, instance: Any) -> None:
        """Register a singleton instance for an interface."""
        cls._instances[interface] = instance

    @classmethod
    def register_factory(cls, interface: type, factory: Callable[[], Any]) -> None:
        """Register a factory function for an interface."""
        cls._factories[interface] = factory

    @classmethod
    def get(cls, interface: type) -> Any:
        """Get an instance for an interface.

        First checks for singleton, then factory, then raises KeyError.
        """
        if interface in cls._instances:
            return cls._instances[interface]
        if interface in cls._factories:
            return cls._factories[interface]()
        raise KeyError(f"No provider registered for {interface.__name__}")

    @classmethod
    def has(cls, interface: type) -> bool:
        """Check if a provider is registered for an interface."""
        return interface in cls._instances or interface in cls._factories


def autoparams(func: F) -> F:
    """Decorator that automatically injects dependencies from BccdProvider.

    Use this decorator on methods that need dependency injection.
    Dependencies are resolved by type hints.

    Usage::

        class MyService:
            @autoparams
            def __init__(self, config: Config, store: KnowledgeStore) -> None:
                self.config = config
                self.store = store
    """
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        import inspect

        sig = inspect.signature(func)
        params = sig.parameters

        resolved: dict[str, Any] = {}
        for param_name, param in params.items():
            if param_name in ("self", "cls"):
                continue
            if param_name in kwargs:
                resolved[param_name] = kwargs[param_name]
                continue
            if param.annotation is inspect.Parameter.empty:
                continue
            try:
                resolved[param_name] = BccdProvider.get(param.annotation)
            except KeyError:
                pass

        return func(*args, **resolved)

    return wrapper  # type: ignore


def inject(interface: type) -> Callable[[F], F]:
    """Decorator to inject a dependency by interface type.

    Usage::

        class MyService:
            @inject(Config)
            def set_config(self, config: Config) -> None:
                self._config = config
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            import inspect

            sig = inspect.signature(func)
            params = sig.parameters

            resolved: dict[str, Any] = {}
            for param_name, param in params.items():
                if param_name in ("self", "cls"):
                    continue
                if param_name in kwargs:
                    resolved[param_name] = kwargs[param_name]
                    continue
                if param.annotation is inspect.Parameter.empty:
                    continue
                if param.annotation == interface:
                    try:
                        resolved[param_name] = BccdProvider.get(interface)
                    except KeyError:
                        pass

            return func(*args, **resolved)

        return wrapper  # type: ignore

    return decorator


def configure() -> None:
    """Configure dependency injection for DeepHunter.

    Call this during application startup to wire up all dependencies.
    """
    from deephunter.core.config import DeepHunterConfig
    from deephunter.rag.embeddings import RandomEmbeddingProvider
    from deephunter.rag.retriever import Retriever
    from deephunter.tools.events import ToolEventBus
    from deephunter.tools.registry import ToolPluginRegistry

    config = DeepHunterConfig.default()
    BccdProvider.register_singleton(DeepHunterConfig, config)

    event_bus = ToolEventBus()
    registry = ToolPluginRegistry(event_bus=event_bus)
    registry.discover()
    BccdProvider.register_singleton(ToolPluginRegistry, registry)
    BccdProvider.register_singleton(ToolEventBus, event_bus)

    embedding_provider = RandomEmbeddingProvider()

    def _create_retriever() -> Retriever:
        return Retriever(config.rag, None, embedding_provider=embedding_provider)

    BccdProvider.register_factory(Retriever, _create_retriever)
