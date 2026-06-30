# Model Router & Provider Abstraction Layer v1

Selects the best AI provider and model for a given task.  Completely
provider-independent — no API calls, no API keys, no model-specific logic
in the routing core.

## Architecture

```
Prompt Builder
    │
    ▼
ModelRequest ──→ ModelRouter ──→ RoutingDecision ──→ ModelProvider.generate()
                     │                                      │
                ProviderRegistry                        ModelResponse
                     │
    ┌────────┬───────┼───────┬────────┐
    │        │       │       │        │
  OpenAI  Claude  DeepSeek  Ollama  Gemini...
  (future) (future) (future)  (legacy) (future)
```

## Data Flow

```
ModelRouter.route(request)
    │
    ├── Translate task_type → required capabilities
    ├── Translate require_* flags → required capabilities
    ├── Get candidate providers (AND matching — all caps required)
    ├── Build fallback chain (config default → config fallbacks → candidates)
    ├── Try each provider in chain:
    │   ├── Check is_available()
    │   ├── Select best model
    │   ├── Match capabilities
    │   └── Return RoutingDecision
    └── Raise RouterError if all fail
```

## Core Models

| Model | ID prefix | Purpose |
|-------|-----------|---------|
| `ModelRequest` | `req-` | What the caller needs (task, caps, flags, preferences) |
| `ModelResponse` | `resp-` | Generated content + routing metadata |
| `RoutingDecision` | — | Which provider+model was selected and why |
| `ModelInfo` | — | A model's capabilities, tokens, cost |
| `ProviderMetadata` | — | Provider description, models, API type |
| `ExecutionContext` | — | Derived context from request for internal use |
| `RoutingMetrics` | — | Aggregated routing statistics |

### ModelRequest

```python
request = ModelRequest(
    task_type="reasoning",
    required_capabilities={"code_review"},
    preferred_providers=["claude"],
    excluded_providers=["ollama"],
    require_offline=False,
    require_vision=True,
    require_json_output=True,
    max_tokens=8192,
)
```

### RoutingDecision

```python
decision = RoutingDecision(
    provider_name="openai",
    model_name="gpt-4o",
    reason="Best capability match (attempt 1/3)",
    matched_capabilities=["reasoning", "vision", "large_context"],
    unmatched_capabilities=[],
    attempt_number=1,
    total_attempts=3,
    fallback_chain=["openai", "claude", "ollama"],
)
```

## Capabilities (14 defined)

| Capability | Description |
|------------|-------------|
| `reasoning` | Complex multi-step reasoning |
| `code_generation` | Writing new code |
| `code_review` | Analyzing existing code |
| `large_context` | Handling 100K+ token contexts |
| `vision` | Processing images |
| `tool_use` | Function calling / tool use |
| `json_output` | Reliable JSON mode |
| `streaming` | Token-by-token streaming |
| `long_running` | Extended processing tasks |
| `fast_response` | Low-latency responses |
| `offline` | Runs without internet |
| `cost_efficient` | Low cost per token |
| `safety` | Safety-filtered outputs |
| `structured_output` | Structured/typed output |

## Task Types (13 defined)

| Task | Required Capabilities |
|------|----------------------|
| `reasoning` | reasoning, large_context |
| `planning` | reasoning, structured_output |
| `code_analysis` | code_review, reasoning |
| `code_generation` | code_generation |
| `documentation` | code_review |
| `report_writing` | structured_output, large_context |
| `security_analysis` | reasoning, code_review |
| `threat_modeling` | reasoning, structured_output |
| `knowledge_extraction` | large_context |
| `summarization` | large_context |
| `translation` | (none) |
| `classification` | structured_output |
| `context_compression` | large_context |

## Provider Interface

### ModelProvider (ABC)

The new rich provider interface:

```python
class ModelProvider(ABC):
    @property
    def name(self) -> str: ...
    @property
    def metadata(self) -> ProviderMetadata: ...
    def get_models(self) -> list[ModelInfo]: ...
    def get_model(self, model_name) -> ModelInfo | None: ...
    def is_available(self) -> ProviderStatus: ...
    def generate(self, prompt, system_prompt, temperature, max_tokens, model) -> ModelResponse: ...
    def supports_capability(self, capability) -> bool: ...
    def find_model_by_capability(self, capability) -> list[ModelInfo]: ...
```

### LegacyProviderAdapter

Wraps existing `LLMProvider` implementations for backward compatibility:

```python
from deephunter.llm.ollama_provider import OllamaProvider
from deephunter.router import LegacyProviderAdapter

legacy = OllamaProvider(model="deepseek-coder:6.7b")
adapter = LegacyProviderAdapter(legacy, name="ollama")
router.register_provider(adapter)
```

Capabilities are inferred from the provider name:
- `ollama` → offline, cost_efficient, reasoning, code_generation, code_review
- `openai` → reasoning, code_generation, code_review, json_output, streaming, structured_output, large_context, vision, tool_use, safety, fast_response

## Provider Registry

```python
from deephunter.router import ProviderRegistry, ModelRouter

registry = ProviderRegistry()

# Register
registry.register(my_provider)
registry.register(another_provider)

# Lookup
provider = registry.get("openai")
providers = registry.find_by_capability("vision")
providers = registry.find_by_task("code_analysis")

# List
all_providers = registry.list_providers()
names = registry.list_names()
```

## Model Router

### Usage

```python
from deephunter.router import ModelRouter, ModelRequest
from deephunter.core.config import RouterConfig

config = RouterConfig(
    default_provider="ollama",
    fallback_providers=["openai"],
    max_fallback_attempts=3,
)

router = ModelRouter(config=config)
router.register_provider(my_openai_provider)
router.register_provider(my_ollama_provider)

# Route only (no execution)
request = ModelRequest(task_type="security_analysis")
decision = router.route(request)
print(f"Selected: {decision.provider_name}/{decision.model_name}")
print(f"Reason: {decision.reason}")

# Route + execute
response = router.execute(
    request,
    prompt="Analyze this endpoint for vulnerabilities",
    system_prompt="You are a security expert",
    temperature=0.3,
)
print(response.content)
```

### Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `default_provider` | `"ollama"` | First provider in fallback chain |
| `fallback_providers` | `["openai"]` | Ordered fallback list |
| `enabled_providers` | `["ollama", "openai"]` | Whitelist |
| `disabled_providers` | `[]` | Blacklist |
| `provider_priorities` | `{}` | Custom priority overrides |
| `task_provider_mapping` | `{}` | Task → specific provider |
| `offline_mode` | `False` | Only allow offline-capable providers |
| `simulation_mode` | `False` | Dry-run routing |
| `dry_run` | `False` | Log decisions without executing |
| `max_fallback_attempts` | `3` | Max providers to try |
| `default_max_tokens` | `4096` | Default generation limit |
| `default_timeout` | `120.0` | Default API timeout |

## Events (6 types)

| Event | When |
|-------|------|
| `ProviderSelectedEvent` | Provider selected for request |
| `ProviderFailedEvent` | Provider unavailable or execution failed |
| `FallbackStartedEvent` | Falling back to next provider |
| `RouteCompletedEvent` | Route + execution completed |
| `RouteFailedEvent` | All providers exhausted |
| `ProviderRegisteredEvent` | New provider registered |

```python
router.event_bus.subscribe(ProviderSelectedEvent, lambda e:
    print(f"Selected {e.provider_name}/{e.model_name} "
          f"(attempt {e.attempt_number})"))
router.event_bus.subscribe(RouteFailedEvent, lambda e:
    print(f"Routing failed after {e.attempts_made} attempts: {e.error}"))
```

## Adding a New Provider

No core modifications needed:

```python
from deephunter.router import ModelProvider, ModelRouter
from deephunter.router.models import ModelInfo, ProviderMetadata, ProviderStatus, ModelResponse

class MyLocalProvider(ModelProvider):
    @property
    def name(self) -> str:
        return "my_provider"

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            name="my_provider",
            models=[
                ModelInfo(
                    id="my-model",
                    name="My Model",
                    capabilities={"reasoning", "offline", "cost_efficient"},
                    max_tokens=4096,
                )
            ],
            default_model="my-model",
            environment="local",
        )

    def is_available(self) -> ProviderStatus:
        return ProviderStatus.AVAILABLE

    def generate(self, prompt, system_prompt=None, temperature=None,
                 max_tokens=None, model=None) -> ModelResponse:
        return ModelResponse(content="Generated result", model="my-model", provider="my_provider")

    # ... implement remaining abstract methods

router = ModelRouter()
router.register_provider(MyLocalProvider())
```

## Backward Compatibility

The existing `LLMProvider` ABC, `LLMResponse` dataclass, and
`LLMProviderFactory` in `llm/base.py` are unchanged.  Legacy providers work
via `LegacyProviderAdapter`.

```python
from deephunter.llm.base import LLMProviderFactory
from deephunter.router import LegacyProviderAdapter, ModelRouter

config = DeepHunterConfig.default()
legacy = LLMProviderFactory.create(config.llm)
adapter = LegacyProviderAdapter(legacy, name=config.llm.provider)

router = ModelRouter()
router.register_provider(adapter)
```

## File Layout

```
src/deephunter/router/
├── __init__.py           # Public API (30+ symbols)
├── models.py             # ModelRequest, ModelResponse, RoutingDecision, etc.
├── capabilities.py       # Capability + TaskType enums + task→capability map
├── events.py             # RouterEventBus + 6 events
├── provider.py           # ModelProvider ABC + LegacyProviderAdapter
├── registry.py           # ProviderRegistry (plugin discovery)
├── router.py             # ModelRouter (routing engine)
└── config.py             # Re-exports RouterConfig

src/deephunter/core/
├── config.py             # + RouterConfig (14 fields)
├── exceptions.py         # + RouterError
└── __init__.py           # + RouterConfig, RouterError exports

tests/unit/
├── test_router_models.py         # 18 tests
├── test_router_capabilities.py   # 8 tests
├── test_router_events.py         # 13 tests
├── test_router_provider.py       # 11 tests
├── test_router_registry.py       # 12 tests
├── test_router.py                # 23 tests
└── test_router_integration.py    # 11 tests
```

## Extension Points

| Point | What to extend | How |
|-------|---------------|-----|
| **New capabilities** | Add to `Capability` enum + `TASK_CAPABILITY_MAP` | Edit `capabilities.py` |
| **New task types** | Add to `TaskType` enum + map | Edit `capabilities.py` |
| **New providers** | Subclass `ModelProvider` | Register via `registry.register()` |
| **Legacy providers** | Wrap via `LegacyProviderAdapter` | Pass existing `LLMProvider` |
| **Custom routing logic** | Override `_get_candidates()` or `_build_fallback_chain()` | Subclass `ModelRouter` |
| **Custom capability inference** | Override in `ModelProvider.supports_capability()` | Per-provider |
| **New events** | Subclass `RouterEvent` + add to `RouterEventBus` | Add to `events.py` |
| **CLI commands** | `deephunter providers`, `deephunter models`, `deephunter route` | Add Click commands in `cli/main.py` |

## Migration from LLMProviderFactory

Old pattern (static factory):
```python
provider = LLMProviderFactory.create(config.llm)
response = provider.generate(prompt="...")
```

New pattern (registry + router):
```python
router = ModelRouter(config=config.router)
adapter = LegacyProviderAdapter(LLMProviderFactory.create(config.llm), name=config.llm.provider)
router.register_provider(adapter)

request = ModelRequest(task_type="reasoning", max_tokens=config.llm.max_tokens)
response = router.execute(request, prompt="...", system_prompt=system, temperature=config.llm.temperature)
```

The old pattern continues to work.  The new pattern adds routing, fallback,
capability matching, and metrics.
