"""Provider registry with fallback chains and health monitoring.

Provides intelligent provider selection with fallback routing,
health checks, cost-aware and latency-aware selection.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from deephunter.llm.base import LLMProvider, LLMProviderFactory, LLMResponse
from deephunter.llm.metrics import ProviderMetrics, ProviderStatus, get_metrics_collector
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class SelectionStrategy(str, Enum):
    """Strategy for provider selection."""

    COST_AWARE = "cost_aware"
    LATENCY_AWARE = "latency_aware"
    RELIABILITY_FIRST = "reliability_first"
    CAPABILITY_FIRST = "capability_first"
    MANUAL = "manual"


@dataclass
class ProviderConfig:
    """Configuration for a registered provider."""

    name: str
    provider: LLMProvider
    priority: int = 0
    enabled: bool = True
    max_cost_per_1m_tokens: float = 10.0
    capabilities: list[str] = field(default_factory=list)
    preferred_for: list[str] = field(default_factory=list)
    health_check_interval: int = 60
    last_health_check: datetime | None = None
    status: ProviderStatus = ProviderStatus.UNKNOWN


class ProviderRegistry:
    """Registry with fallback chains, health monitoring, and intelligent routing."""

    _instance: "ProviderRegistry | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "ProviderRegistry":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._providers = {}
                    cls._instance._lock = threading.Lock()
                    cls._instance._metrics = get_metrics_collector()
                    cls._instance._default_strategy = SelectionStrategy.RELIABILITY_FIRST
        return cls._instance

    @classmethod
    def get_instance(cls) -> "ProviderRegistry":
        return cls()

    def register_provider(
        self,
        name: str,
        provider: LLMProvider,
        priority: int = 0,
        capabilities: list[str] | None = None,
        preferred_for: list[str] | None = None,
        max_cost_per_1m: float = 10.0,
    ) -> None:
        with self._lock:
            config = ProviderConfig(
                name=name,
                provider=provider,
                priority=priority,
                capabilities=capabilities or [],
                preferred_for=preferred_for or [],
                max_cost_per_1m_tokens=max_cost_per_1m,
            )
            self._providers[name] = config
            logger.info(f"Registered provider: {name} (priority={priority})")

    def unregister_provider(self, name: str) -> bool:
        with self._lock:
            return bool(self._providers.pop(name, None))

    def get_provider(self, name: str) -> ProviderConfig | None:
        with self._lock:
            return self._providers.get(name)

    def list_providers(self, enabled_only: bool = True) -> list[ProviderConfig]:
        with self._lock:
            providers = list(self._providers.values())
            if enabled_only:
                providers = [p for p in providers if p.enabled]
            return sorted(providers, key=lambda x: x.priority, reverse=True)

    def get_fallback_chain(
        self,
        required_capabilities: list[str] | None = None,
        preferred_provider: str | None = None,
        strategy: SelectionStrategy | None = None,
    ) -> list[ProviderConfig]:
        strat = strategy or self._default_strategy
        providers = self.list_providers(enabled_only=True)

        if not providers:
            return []

        candidates: list[ProviderConfig] = []
        for p in providers:
            if required_capabilities:
                if not all(cap in p.capabilities for cap in required_capabilities):
                    continue
            candidates.append(p)

        if not candidates:
            return providers[:3]

        if strat == SelectionStrategy.LATENCY_AWARE:
            candidates = sorted(candidates, key=lambda p: self._get_provider_latency(p.name))
        elif strat == SelectionStrategy.COST_AWARE:
            candidates = sorted(candidates, key=lambda p: p.max_cost_per_1m_tokens)
        elif strat == SelectionStrategy.RELIABILITY_FIRST:
            candidates = sorted(candidates, key=lambda p: self._get_provider_health_score(p.name), reverse=True)

        if preferred_provider:
            pref = next((p for p in candidates if p.name == preferred_provider), None)
            if pref:
                candidates.remove(pref)
                candidates.insert(0, pref)

        return candidates

    def execute_with_fallback(
        self,
        messages: list[Any],
        strategy: SelectionStrategy = SelectionStrategy.RELIABILITY_FIRST,
        preferred_provider: str | None = None,
        required_capabilities: list[str] | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        chain = self.get_fallback_chain(
            required_capabilities=required_capabilities,
            preferred_provider=preferred_provider,
            strategy=strategy,
        )

        if not chain:
            raise RuntimeError("No available providers in fallback chain")

        last_error: Exception | None = None
        for config in chain:
            try:
                start = time.monotonic()
                response = config.provider.generate(messages, **kwargs)
                latency_ms = (time.monotonic() - start) * 1000
                self._metrics.record_request(
                    provider=config.name,
                    model=getattr(config.provider, "_model", "unknown"),
                    latency_ms=latency_ms,
                    prompt_tokens=response.usage.get("prompt_tokens", 0),
                    completion_tokens=response.usage.get("completion_tokens", 0),
                )
                return response
            except Exception as exc:
                last_error = exc
                logger.warning(f"Provider {config.name} failed: {exc}. Trying next fallback.")
                self._metrics.get_provider_metrics(config.name).record_failure()
                continue

        raise RuntimeError(f"All providers in fallback chain failed. Last error: {last_error}") from last_error

    def check_health(self, name: str) -> ProviderStatus:
        config = self.get_provider(name)
        if not config:
            return ProviderStatus.UNKNOWN

        try:
            healthy = config.provider.check_health()
            config.status = ProviderStatus.HEALTHY if healthy else ProviderStatus.UNAVAILABLE
            config.last_health_check = datetime.now(UTC)
            return config.status
        except Exception:
            config.status = ProviderStatus.UNAVAILABLE
            config.last_health_check = datetime.now(UTC)
            return ProviderStatus.UNAVAILABLE

    def check_all_health(self) -> dict[str, ProviderStatus]:
        results = {}
        for name in list(self._providers.keys()):
            results[name] = self.check_health(name)
        return results

    def enable_provider(self, name: str) -> bool:
        config = self.get_provider(name)
        if config:
            config.enabled = True
            return True
        return False

    def disable_provider(self, name: str) -> bool:
        config = self.get_provider(name)
        if config:
            config.enabled = False
            return True
        return False

    def set_strategy(self, strategy: SelectionStrategy) -> None:
        self._default_strategy = strategy

    def get_metrics(self, provider_name: str | None = None) -> dict[str, Any]:
        if provider_name:
            config = self.get_provider(provider_name)
            if config:
                return self._metrics.get_provider_metrics(config.name).get_summary()
            return {}
        return self._metrics.get_all_summaries()

    def _get_provider_latency(self, name: str) -> float:
        stats = self._metrics.get_provider_metrics(name).get_latency_stats()
        return stats.get("avg_ms", float("inf"))

    def _get_provider_health_score(self, name: str) -> float:
        m = self._metrics.get_provider_metrics(name)
        if m.total_requests == 0:
            return 1.0
        success_rate = (m.total_requests - m.failed_requests) / m.total_requests
        return success_rate

    def set_provider_priority(self, name: str, priority: int) -> bool:
        config = self.get_provider(name)
        if config:
            config.priority = priority
            return True
        return False


def get_provider_registry() -> ProviderRegistry:
    return ProviderRegistry.get_instance()