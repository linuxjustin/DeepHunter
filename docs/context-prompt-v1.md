# Context Engine & Prompt Builder v1

The bridge between DeepHunter's Knowledge/Reasoning/Planning engines
and future AI models.  Completely model-independent — no AI, no LLM,
no embeddings, no RAG.

## Architecture

```
Knowledge Engine ─┐
Reasoning Engine ─┤
Investigation Planner ─┤
User Query ───────────┤
User Constraints ─────┤
Future Sources ───────┤
                     Context Engine ──→ Prompt Builder ──→ AI Model
                     (gather+organize)    (format)         (future)
```

Two independent subsystems:

| Subsystem | Responsibility |
|-----------|---------------|
| **Context Engine** | Gather, deduplicate, prioritize, budget, produce structured Context |
| **Prompt Builder** | Transform Context into model-ready prompts with templates + formats |

## Context Engine

### Data Flow

```
ContextEngine.build()
    │
    ├── InitContextStage     — set metadata IDs
    ├── CollectUserInput     — query + constraints
    ├── CollectSession       — InvestigationSession data
    ├── CollectPlan          — InvestigationPlan data
    ├── DeduplicateStage     — remove duplicate blocks
    ├── PrioritizeStage      — sort blocks by priority desc
    ├── BudgetStage          — trim to token budget
    └── RecalculateStage     — update statistics
    │
    └── Context object
```

### Core Models

| Model | ID prefix | Purpose |
|-------|-----------|---------|
| `Context` | `ctx-` | Top-level container (sections, sources, references, statistics) |
| `ContextSection` | `cs-` | Named section of related blocks |
| `ContextBlock` | `cb-` | Single content block with importance, priority, source |
| `ContextSource` | — | Metadata about where data came from |
| `ContextReference` | — | CVE, CWE, writeup, payload reference |
| `ContextBudget` | — | Token budget configuration |
| `ContextStatistics` | — | Counts, tokens, distribution stats |

### Source Types (28 defined)

`ContextSourceType` enum: `KNOWLEDGE_STORE`, `REASONING_SESSION`,
`INVESTIGATION_PLAN`, `USER_QUERY`, `USER_CONSTRAINTS`,
`TECHNOLOGY_FINGERPRINT`, `FRAMEWORK_DETECTION`, `AUTHENTICATION_STATE`,
`AUTHORIZATION_STATE`, `BUSINESS_LOGIC`, `CLOUD_INFORMATION`,
`INTERESTING_HEADERS`, `INTERESTING_COOKIES`, `INTERESTING_PARAMETERS`,
`INTERESTING_ENDPOINTS`, `PREVIOUS_FINDINGS`, `PREVIOUS_EVIDENCE`,
`USER_NOTES`, `RELATED_CVES`, `RELATED_CWES`, `RELATED_WRITEUPS`,
`RELATED_PAYLOADS`, `FRAMEWORK_DOCUMENTATION`, `TOOL_RESULTS`,
`SCANNER_RESULTS`, `BURP_INTEGRATION`, `MCP_TOOLS`, `OTHER`

### Importance Levels

`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`

Used for:
- Budget protection (CRITICAL/HIGH blocks kept above `min_important_tokens`)
- Prioritization ordering

### Usage

```python
from deephunter.context import ContextEngine
from deephunter.reasoning.session import InvestigationSession
from deephunter.planning import Planner

# Build context from session + plan
session = InvestigationSession.new("https://example.com")
planner = Planner()
plan_result = planner.plan_from_session(session)

engine = ContextEngine()
context = engine.build(
    investigation_id=session.investigation.id,
    plan_id=plan_result.plan.id,
    session=session,
    plan=plan_result.plan,
    query="Find authentication bypasses",
    constraints=["No destructive testing"],
)

# Save and load
engine.save_context(context, "/tmp/context.json")
loaded = engine.load_context("/tmp/context.json")

# Access data
for section in context.sections:
    print(f"Section: {section.name} ({len(section.blocks)} blocks)")
    for block in section.blocks:
        print(f"  [{block.importance.value}] {block.summary}")
```

### Source Collectors

| Function | Source | Purpose |
|----------|--------|---------|
| `collect_from_session()` | InvestigationSession | Target, tech, observations, evidence, findings |
| `collect_from_plan()` | InvestigationPlan | Plan summary + individual steps |
| `collect_from_query()` | String | User query text |
| `collect_from_constraints()` | List[str] | User constraints |
| `merge_contexts()` | List[Context] | Merge multiple context objects |

### Extension Points

| Point | How |
|-------|-----|
| **New source collectors** | Write a function that takes Context and returns Context |
| **Custom pipeline stages** | Subclass `ContextStage`, implement `process()` |
| **Custom budget algorithms** | Modify `apply_budget()` or provide new budget function |
| **Event subscribers** | Subscribe to any `ContextEvent` on `engine.event_bus` |

## Prompt Builder

### Data Flow

```
PromptBuilder.build(context, style, format, adapter)
    │
    ├── Resolve template     — find by name or style
    ├── Build system message — from template or fallback
    ├── Build user message   — from template or context sections
    ├── Build developer msg  — from template if present
    ├── Add references       — from context
    ├── Apply format         — markdown / plain_text / json / structured
    ├── Apply adapter        — model-specific transformation
    └── Recalculate stats    — token counts, cost estimation
    │
    └── Prompt object
```

### Core Models

| Model | ID prefix | Purpose |
|-------|-----------|---------|
| `Prompt` | `prompt-` | Complete prompt with messages + metadata |
| `PromptMessage` | — | Single message (role, content, name) |
| `PromptTemplate` | — | Configurable template with variables |
| `PromptMetadata` | — | Style, format, adapter, tags |
| `PromptStatistics` | — | Token counts, cost, distribution |

### Prompt Styles (6 built-in)

| Style | Purpose |
|-------|---------|
| `REASONING` | Hypothesis generation |
| `PLANNING` | Plan refinement |
| `CODE_REVIEW` | Security code review |
| `INVESTIGATION` | Full investigation analysis (default) |
| `REPORTING` | Security report generation |
| `LEARNING` | Educational/learning scenarios |

### Output Formats

| Format | Class | Output |
|--------|-------|--------|
| `markdown` | `MarkdownFormatter` | `### System Message` headings |
| `plain_text` | `PlainTextFormatter` | `[SYSTEM]` role prefixes |
| `json` | `JSONFormatter` | Complete JSON object |
| `structured` | `StructuredFormatter` | XML-like `<prompt>` tags |

### Built-in Templates (6)

| ID | Style | Variables |
|----|-------|-----------|
| `investigation_default` | INVESTIGATION | target_info, technology_fingerprint, observations, evidence, findings, investigation_plan, user_query, constraints |
| `reasoning_default` | REASONING | context_summary |
| `planning_default` | PLANNING | context_summary, investigation_plan |
| `code_review_default` | CODE_REVIEW | context_summary |
| `reporting_default` | REPORTING | context_summary |
| *(fallback per style)* | any | context_summary |

### Usage

```python
from deephunter.context import ContextEngine
from deephunter.prompt import PromptBuilder, PromptStyle, PromptFormat

# Build context
engine = ContextEngine()
context = engine.build(query="Analyze authentication")

# Build prompt
builder = PromptBuilder()
prompt = builder.build(
    context,
    style=PromptStyle.INVESTIGATION,
    fmt=PromptFormat.MARKDOWN,
)

# Access messages
system, user = prompt.to_system_user()
print(system)
print(user)

# Statistics
print(f"Tokens: {prompt.statistics.estimated_tokens}")
print(f"Cost: ${prompt.statistics.estimated_cost:.6f}")

# Save/load
builder.save_prompt(prompt, "/tmp/prompt.json")
loaded = builder.load_prompt("/tmp/prompt.json")
```

### Custom Templates

```python
from deephunter.prompt import PromptBuilder, PromptStyle
from deephunter.prompt.models import PromptTemplate

builder = PromptBuilder()
builder.template_registry.register(PromptTemplate(
    id="my_custom",
    name="Custom Investigation",
    style=PromptStyle.INVESTIGATION,
    system_template="You are a specialized API security tester.",
    user_template="""# Target
{{ target_information }}

# Tech Stack
{{ technology_fingerprint }}

Analyze the above for API vulnerabilities.""",
    variables=["target_information", "technology_fingerprint"],
))

prompt = builder.build(context, template_name="my_custom")
```

### Custom Adapters

```python
from deephunter.prompt import PromptBuilder
from deephunter.prompt.adapters import ModelAdapter
from deephunter.prompt.models import Prompt

class MyClaudeAdapter(ModelAdapter):
    @property
    def name(self) -> str:
        return "my_claude"

    def adapt(self, prompt: Prompt) -> Prompt:
        # Transform for Claude's expected format
        return prompt

    def estimate_tokens(self, text: str) -> int:
        return len(text) // 4

builder = PromptBuilder()
builder.register_adapter("my_claude", MyClaudeAdapter())

prompt = builder.build(context, adapter_name="my_claude")
```

## Events

### Context Events (6)

| Event | When |
|-------|------|
| `ContextCreatedEvent` | New context initialized |
| `ContextUpdatedEvent` | Context updated |
| `ContextTrimmedEvent` | Token budget trimmed |
| `ContextMergeEvent` | Multiple contexts merged |
| `ContextDeduplicatedEvent` | Duplicates removed |
| `ContextBudgetExceededEvent` | Budget exceeded, action taken |

### Prompt Events (5)

| Event | When |
|-------|------|
| `PromptGeneratedEvent` | Prompt built |
| `PromptTemplateLoadedEvent` | Template resolved |
| `PromptTemplateNotFoundEvent` | Template missing |
| `PromptFormatAppliedEvent` | Format applied |
| `PromptAdapterAppliedEvent` | Adapter applied |

### Event Bus Pattern

All event buses follow the same pattern as `ReasoningEventBus`,
`PlanningEventBus`, and ingestion `EventBus`:

```python
bus = ContextEventBus()
bus.subscribe(ContextCreatedEvent, lambda e: print(f"Context: {e.context_id}"))
bus.emit(ContextCreatedEvent(context_id="ctx-1"))
```

## File Layout

```
src/deephunter/context/
├── __init__.py       # Public API (50+ symbols)
├── models.py         # Context, ContextBlock, ContextSection, etc.
├── events.py         # ContextEventBus + 6 events
├── budget.py         # Token estimation + budget application
├── sources.py        # Source collectors (session, plan, query, etc.)
├── pipeline.py       # ContextPipeline + 8 stages
├── engine.py         # ContextEngine facade
└── config.py         # Re-exports ContextConfig

src/deephunter/prompt/
├── __init__.py       # Public API (40+ symbols)
├── models.py         # Prompt, PromptMessage, PromptTemplate, etc.
├── events.py         # PromptEventBus + 5 events
├── templates.py      # TemplateRegistry + 6 built-in templates
├── formats.py        # 4 formatters (markdown, plain, json, structured)
├── adapters.py       # ModelAdapter ABC + IdentityAdapter
├── builder.py        # PromptBuilder facade
└── config.py         # Re-exports PromptConfig

tests/unit/
├── test_context_models.py       # 18 tests
├── test_context_events.py       # 13 tests
├── test_context_budget.py       # 7 tests
├── test_context_sources.py      # 8 tests
├── test_context_pipeline.py     # 16 tests
├── test_context_engine.py       # 12 tests
├── test_prompt_models.py        # 18 tests
├── test_prompt_events.py        # 12 tests
├── test_prompt_templates.py     # 10 tests
├── test_prompt_formats.py       # 8 tests
├── test_prompt_adapters.py      # 5 tests
└── test_prompt_builder.py       # 14 tests
```

## Extension Points

| Point | What to extend | How |
|-------|---------------|-----|
| **New context sources** | Sources from future tools | Write `collect_from_*()` function |
| **New pipeline stages** | Context transformation | Subclass `ContextStage` |
| **New budget algorithms** | Token estimation | Modify `budget.py` |
| **New prompt styles** | New investigation scenarios | Add `PromptStyle` + template |
| **New templates** | Custom prompt formats | Register via `TemplateRegistry` |
| **New formats** | Custom output format | Subclass `PromptFormatter` |
| **New adapters** | Model-specific formatting | Subclass `ModelAdapter` |
| **New events** | Custom observability | Subclass base event |
| **CLI commands** | `deephunter context`, `deephunter prompt` | Add Click commands in `cli/main.py` |

## CLI Preparation

The engine and builder expose interfaces ready for future CLI commands:

```bash
# Future commands (not yet implemented)
deephunter context <investigation-id>
deephunter prompt <context-id> [--style investigation] [--format json]
deephunter explain <target>
```

## Migration from Legacy

The old `PromptBuilderContext` / `PromptBuilderContextBuilder` in
`reasoning/prompt_builder.py` continues to work unchanged.  The new
Context Engine and Prompt Builder are superior replacements that
should be used for all new code.

Key differences:
- Old: Reasoning-only, no token budgeting, no event bus
- New: Multi-source (session + plan + query + constraints), dedicated event bus, token budget, 6 prompt styles, 4 output formats, model adapters
