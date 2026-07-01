"""Model Router — selects the best provider+model for a given task.

Completely provider-independent.  Routing decisions are based on
capabilities, task type, configuration, and fallback chains.
"""

from __future__ import annotations

import time
from typing import Any

from deephunter.router.capabilities import (
    Capability,
    get_capabilities_for_task_str,
)
from deephunter.router.events import (
    FallbackStartedEvent,
    ProviderFailedEvent,
    ProviderSelectedEvent,
    RouteCompletedEvent,
    RouteFailedEvent,
    RouterEventBus,
)
from deephunter.router.models import (
    ModelRequest,
    ModelResponse,
    ProviderStatus,
    RoutingDecision,
    RoutingMetrics,
)
from deephunter.router.provider import ModelProvider
from deephunter.router.registry import ProviderRegistry

from deephunter.core.config import RouterConfig
from deephunter.core.exceptions import RouterError


class ModelRouter:
    """Selects the best provider and model for a task.

    Usage::

        router = ModelRouter()
        router.register_providers_from_config(config)

        decision = router.route(ModelRequest(task_type="reasoning"))
        response = router.execute(ModelRequest(...), prompt="Analyze this")
    """

    def __init__(
        self,
        registry: ProviderRegistry | None = None,
        config: RouterConfig | None = None,
        event_bus: RouterEventBus | None = None,
    ) -> None:
        self._registry = registry or ProviderRegistry()
        self._config = config or RouterConfig()
        self._event_bus = event_bus or RouterEventBus()
        self._metrics = RoutingMetrics()

    # ── Registration ──────────────────────────────────────────────

    def register_provider(self, provider: ModelProvider) -> None:
        """Register a single provider."""
        self._registry.register(provider)

    def deregister_provider(self, name: str) -> None:
        """Remove a provider by name."""
        self._registry.deregister(name)

    def get_provider(self, name: str) -> ModelProvider | None:
        """Get a registered provider by name."""
        return self._registry.get(name)

    def list_providers(self) -> list[ModelProvider]:
        """Return all registered providers."""
        return self._registry.list_providers()

    # ── Routing ──────────────────────────────────────────────────

    def route(self, request: ModelRequest) -> RoutingDecision:
        """Select the best provider and model for a request.

        Does NOT execute the model.  Only returns a routing decision.

        Args:
            request: The model request describing what is needed.

        Returns:
            A RoutingDecision with the selected provider and model.

        Raises:
            RouterError: If no suitable provider is found.
        """
        start = time.perf_counter()
        self._metrics.total_requests += 1

        # Build execution context from request
        task_caps = get_capabilities_for_task_str(request.task_type)
        require_caps = self._require_flags_to_capabilities(request)
        all_required = set(request.required_capabilities) | task_caps | require_caps

        # Get candidate providers
        candidates = self._get_candidates(all_required, request)

        if not candidates:
            self._metrics.failed_routes += 1
            self._event_bus.emit(RouteFailedEvent(
                request_id=request.id,
                error="No suitable provider found",
                attempts_made=0,
            ))
            raise RouterError(
                f"No provider found for task '{request.task_type}' "
                f"with capabilities {all_required}"
            )

        # Build fallback chain from config + candidates
        fallback_chain = self._build_fallback_chain(candidates, request)
        if not fallback_chain:
            self._metrics.failed_routes += 1
            self._event_bus.emit(RouteFailedEvent(
                request_id=request.id,
                error="Fallback chain is empty",
                attempts_made=0,
            ))
            raise RouterError("No providers available in fallback chain")

        # Try each provider in the chain
        errors: list[str] = []
        for attempt, provider_name in enumerate(fallback_chain):
            provider = self._registry.get(provider_name)
            if provider is None:
                errors.append(f"Provider '{provider_name}' not found in registry")
                continue

            status = provider.is_available()
            if status != ProviderStatus.AVAILABLE:
                err = f"Provider '{provider_name}' status is {status.value}"
                errors.append(err)
                self._event_bus.emit(ProviderFailedEvent(
                    request_id=request.id,
                    provider_name=provider_name,
                    error=err,
                ))
                if attempt + 1 < len(fallback_chain):
                    self._event_bus.emit(FallbackStartedEvent(
                        request_id=request.id,
                        failed_provider=provider_name,
                        fallback_provider=fallback_chain[attempt + 1],
                        attempt_number=attempt + 2,
                    ))
                continue

            # Select model
            model_name = self._select_model(provider, request)

            matched, unmatched = self._match_capabilities(provider, all_required)

            decision = RoutingDecision(
                provider_name=provider_name,
                model_name=model_name,
                reason=f"Provider '{provider_name}' selected (attempt {attempt + 1}/{len(fallback_chain)})",
                matched_capabilities=list(matched),
                unmatched_capabilities=list(unmatched),
                attempt_number=attempt + 1,
                total_attempts=len(fallback_chain),
                fallback_chain=fallback_chain,
            )

            elapsed = (time.perf_counter() - start) * 1000
            self._successful_route(decision, request.task_type, elapsed)

            self._event_bus.emit(ProviderSelectedEvent(
                request_id=request.id,
                provider_name=provider_name,
                model_name=model_name,
                reason=decision.reason,
                attempt_number=attempt + 1,
            ))

            return decision

        # All attempts failed
        self._metrics.failed_routes += 1
        elapsed = (time.perf_counter() - start) * 1000
        self._metrics.average_routing_ms = (
            (self._metrics.average_routing_ms * (self._metrics.total_requests - 1) + elapsed)
            / self._metrics.total_requests
        )

        self._event_bus.emit(RouteFailedEvent(
            request_id=request.id,
            error="; ".join(errors),
            attempts_made=len(fallback_chain),
        ))

        raise RouterError(
            f"All {len(fallback_chain)} providers failed for task '{request.task_type}': "
            + "; ".join(errors)
        )

    def execute(
        self,
        request: ModelRequest,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> ModelResponse:
        """Route a request AND execute it against the selected provider.

        Args:
            request: The model request.
            prompt: The prompt text to send.
            system_prompt: Optional system instruction.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            tools: Optional tool definitions to pass to the model.

        Returns:
            A ModelResponse with content and routing metadata.

        Raises:
            RouterError: If routing or execution fails.
        """
        decision = self.route(request)

        provider_names = [decision.provider_name] + list(decision.fallback_chain)
        last_exc: Exception | None = None

        for provider_name in provider_names:
            provider = self._registry.get(provider_name)
            if provider is None:
                continue

            try:
                response = provider.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens or request.max_tokens,
                    model=decision.model_name,
                    tools=tools,
                )
                response.request_id = request.id
                response.routing_decision = decision
                self._metrics.successful_routes += 1
                self._metrics.model_counts[decision.model_name] = (
                    self._metrics.model_counts.get(decision.model_name, 0) + 1
                )
                self._event_bus.emit(RouteCompletedEvent(
                    request_id=request.id,
                    provider_name=provider_name,
                    model_name=decision.model_name,
                ))
                return response
            except Exception as exc:
                last_exc = exc
                self._event_bus.emit(ProviderFailedEvent(
                    request_id=request.id,
                    provider_name=provider_name,
                    model_name=decision.model_name,
                    error=str(exc),
                ))
                continue

        raise RouterError(
            f"All providers failed. Last error: {last_exc}"
        ) from last_exc

    # ── Internal ─────────────────────────────────────────────────

    @staticmethod
    def _require_flags_to_capabilities(request: ModelRequest) -> set[str]:
        """Translate ``require_*`` flags on a ModelRequest to capabilities."""
        caps: set[str] = set()
        if request.require_offline:
            caps.add("offline")
        if request.require_streaming:
            caps.add("streaming")
        if request.require_vision:
            caps.add("vision")
        if request.require_json_output:
            caps.add("json_output")
        if request.require_tool_use:
            caps.add("tool_use")
        return caps

    def _get_candidates(
        self,
        required_caps: set[str],
        request: ModelRequest,
    ) -> list[ModelProvider]:
        """Get candidate providers, filtered by capabilities (AND logic) and exclusions."""
        candidates: list[ModelProvider] = []

        # If preferred providers are specified, try those first
        if request.preferred_providers:
            for name in request.preferred_providers:
                provider = self._registry.get(name)
                if provider and provider.name not in request.excluded_providers:
                    if not required_caps or all(
                        provider.supports_capability(c) for c in required_caps
                    ):
                        candidates.append(provider)
            if candidates:
                return candidates

        # Capability-based search (AND — all required capabilities must be supported)
        all_providers = [
            p for p in self._registry.list_providers()
            if p.name not in request.excluded_providers
        ]
        for provider in all_providers:
            if not required_caps or all(
                provider.supports_capability(c) for c in required_caps
            ):
                candidates.append(provider)

        return candidates

    def _build_fallback_chain(
        self,
        candidates: list[ModelProvider],
        request: ModelRequest,
    ) -> list[str]:
        """Build an ordered fallback chain from candidates + config."""
        chain: list[str] = []
        seen: set[str] = set()

        # 1. Config default provider
        default = self._config.default_provider
        if default and default not in seen:
            if any(c.name == default for c in candidates):
                chain.append(default)
                seen.add(default)

        # 2. Config fallback providers
        for fb in self._config.fallback_providers:
            if fb not in seen and any(c.name == fb for c in candidates):
                chain.append(fb)
                seen.add(fb)

        # 3. Remaining candidates sorted by config priority
        for candidate in candidates:
            if candidate.name not in seen:
                chain.append(candidate.name)
                seen.add(candidate.name)

        # 4. Apply max attempts limit
        max_attempts = self._config.max_fallback_attempts
        if max_attempts > 0:
            chain = chain[:max_attempts]

        return chain

    def _select_model(self, provider: ModelProvider, request: ModelRequest) -> str:
        """Select the best model from a provider for a request."""
        models = provider.get_models()
        if not models:
            return provider.metadata.default_model or provider.name

        # If we have capabilities, find the first model that supports them
        caps = get_capabilities_for_task_str(request.task_type)
        if caps:
            for model in models:
                if caps.issubset(set(model.capabilities)):
                    return model.name or model.id

        # Return the first model with sufficient max_tokens
        for model in models:
            if model.max_tokens >= request.max_tokens:
                return model.name or model.id

        return models[0].name or models[0].id

    def _match_capabilities(
        self, provider: ModelProvider, required: set[str]
    ) -> tuple[set[str], set[str]]:
        """Check which required capabilities a provider supports."""
        matched: set[str] = set()
        unmatched: set[str] = set()
        for cap in required:
            if provider.supports_capability(cap):
                matched.add(cap)
            else:
                unmatched.add(cap)
        return matched, unmatched

    def _successful_route(self, decision: RoutingDecision, task_type: str, elapsed_ms: float) -> None:
        self._metrics.successful_routes += 1
        if decision.attempt_number > 1:
            self._metrics.fallbacks_used += 1
        self._metrics.provider_counts[decision.provider_name] = (
            self._metrics.provider_counts.get(decision.provider_name, 0) + 1
        )
        self._metrics.model_counts[decision.model_name] = (
            self._metrics.model_counts.get(decision.model_name, 0) + 1
        )
        self._metrics.task_counts[task_type] = (
            self._metrics.task_counts.get(task_type, 0) + 1
        )
        n = self._metrics.total_requests
        self._metrics.average_routing_ms = (
            (self._metrics.average_routing_ms * (n - 1) + elapsed_ms) / n
        )

    # ── Properties ────────────────────────────────────────────────

    @property
    def registry(self) -> ProviderRegistry:
        return self._registry

    @property
    def config(self) -> RouterConfig:
        return self._config

    @property
    def event_bus(self) -> RouterEventBus:
        return self._event_bus

    @property
    def metrics(self) -> RoutingMetrics:
        return self._metrics
