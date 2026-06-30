# Expert Methodology Packs v1

## Overview

The Expert Methodology Packs Framework encodes 20+ years of collective bug
bounty methodology into reusable, versioned, structured Methodology Packs.

Each pack represents how experienced security researchers investigate a specific
technology, framework, protocol, or attack surface. Packs plug into the existing
Methodology Engine and Investigation Planner to drive targeted investigation steps.

### Core Design Principles

1. **Structured data, not code** — Each pack is a `MethodologyPack` Pydantic model
   instance that can be serialized, validated, versioned, and loaded dynamically.
2. **Plugin-first** — New packs are registered declaratively via the `PackRegistry`.
3. **Planner integration** — Methodology packs automatically produce
   `InvestigationStep` objects through the `MethodologyPackRule` planning rule.
4. **Framework + cross-cutting** — Framework-specific packs (Laravel, Django, etc.)
   coexist with cross-cutting packs (GraphQL, JWT, Business Logic, etc.) that
   apply across all technologies.

## Architecture

```
src/deephunter/methodology/packs/
├── __init__.py              # Public API re-exports
├── base.py                  # Core data models (MethodologyPack, PackCategory, etc.)
├── registry.py              # PackRegistry, load_all_packs(), validation
├── integration.py           # MethodologyPackRule (planner integration)
├── tests/                   # Test utilities
├── framework/               # Framework-specific packs (12)
│   ├── laravel.py
│   ├── django.py
│   ├── spring_boot.py
│   ├── express.py
│   ├── fastapi.py
│   ├── nextjs.py
│   ├── nuxt.py
│   ├── rails.py
│   ├── aspnet.py
│   ├── wordpress.py
│   ├── drupal.py
│   └── magento.py
└── cross_cutting/           # Cross-cutting packs (10)
    ├── graphql.py
    ├── rest_api.py
    ├── oauth.py
    ├── oidc.py
    ├── jwt.py
    ├── session.py
    ├── file_upload.py
    ├── business_logic.py
    ├── cloud.py
    └── microservices.py
```

## Pack Format

Every pack is a `MethodologyPack` instance with the following structure:

```python
MethodologyPack(
    name="Laravel",                    # Unique pack identifier
    version="1.0.0",                   # Semantic version
    category=PackCategory.FRAMEWORK,   # FRAMEWORK, CROSS_CUTTING, PROTOCOL, etc.
    description="...",                 # Pack description
    supported_technologies=[...],      # Tech names this pack covers
    supported_frameworks=[...],        # Framework names this pack covers
    supported_languages=[...],         # Programming languages
    attack_surface_areas=[...],        # Attack surface areas (authentication, api, etc.)
    investigation_priority=85,         # 0-100 priority
    dependencies=[],                   # Pack dependencies
    related_packs=[...],              # Related pack names
    profile=PackFrameworkProfile(...), # Framework profile (framework packs only)
    workflow=[...],                    # Ordered investigation phases
    checklists=[PackChecklist(...)],   # Checklist items with objectives, procedures
    decision_trees=[DecisionTreeNode(...)],  # Decision trees
    planner_rules=[PackPlannerRule(...)],    # Planner priority modifiers
    references=[{...}],               # OWASP, CWE, CAPEC references
    tags=[...],                        # Categorization tags
)
```

### Checklist Items

Each `PackChecklist` contains:

| Field | Description |
|-------|-------------|
| `objective` | Clear testing objective (e.g., "Test Blade SSTI") |
| `description` | Detailed explanation of what to test |
| `procedure` | Step-by-step numbered testing procedure |
| `priority` | critical / high / medium / low |
| `difficulty` | easy / medium / hard |
| `required_evidence` | List of evidence types to collect |
| `expected_result` | What outcome indicates success |
| `bug_classes` | BugClass enums this item targets |
| `dependencies` | IDs of checklist items that should run first |

### Decision Trees

Each pack includes one or more decision trees representing investigator
decision-making. The tree structure supports:

- **Root node**: A question about the attack surface
- **Branches**: Conditions with conclusions or child nodes
- **Nested trees**: Multi-level branching decisions

### Planner Rules

`PackPlannerRule` objects adjust the planner's priority for specific phases
when the pack's technology is detected. Example: when Django is detected,
mass assignment testing priority increases by 0.15.

## Current Pack Inventory

### Framework Packs (12)

| Pack | Items | Rules | Decision Trees |
|------|-------|-------|----------------|
| Laravel | 13 | 3 | 1 |
| Spring Boot | 7 | 3 | 1 |
| Django | 9 | 3 | 1 |
| Express | 7 | 3 | 1 |
| FastAPI | 6 | 2 | 1 |
| Next.js | 7 | 4 | 1 |
| Nuxt | 4 | 2 | 1 |
| Ruby on Rails | 5 | 2 | 1 |
| ASP.NET Core | 5 | 2 | 1 |
| WordPress | 6 | 2 | 1 |
| Drupal | 4 | 2 | 1 |
| Magento | 5 | 2 | 1 |

### Cross-Cutting Packs (10)

| Pack | Items | Rules | Decision Trees |
|------|-------|-------|----------------|
| GraphQL | 6 | 3 | 1 |
| REST API | 8 | 3 | 1 |
| OAuth 2.0 | 7 | 3 | 1 |
| OpenID Connect | 5 | 2 | 1 |
| JWT | 7 | 4 | 1 |
| Session Management | 7 | 3 | 1 |
| File Upload | 6 | 3 | 1 |
| Business Logic | 8 | 3 | 1 |
| Cloud Review | 5 | 2 | 1 |
| Microservices | 7 | 3 | 1 |

**Totals: 22 packs, 144 checklist items, 59 planner rules, 21 decision trees.**

## Usage

```python
# Load all built-in packs
from deephunter.methodology.packs.registry import load_all_packs, get_pack, list_all_packs

load_all_packs()
packs = list_all_packs()
laravel = get_pack("Laravel")

# Access checklist items
for item in laravel.checklists:
    print(f"[{item.priority.upper()}] {item.objective}")

# Convert to engine checklist items
engine_items = laravel.get_checklist_items(engine_checklist=True)

# Query packs by technology
from deephunter.methodology.packs.registry import get_packs_by_technology
packs = get_packs_by_technology("Django")
```

### Planner Integration

The `MethodologyPackRule` (registered at priority 45) automatically generates
`InvestigationStep` objects from loaded packs:

```python
from deephunter.planning.rules import RuleRegistry
from deephunter.planning.models import PlannerContext

registry = RuleRegistry.with_default_rules()
ctx = PlannerContext(
    technologies=["Django", "Python"],
    frameworks=["Django"],
    attack_surface_areas=["authentication", "api"],
)
steps = registry.evaluate_all(ctx)
# Steps include pack-labeled items like:
# "[Django] Identify Django version, settings, and debug mode"
```

### Creating a Custom Pack

```python
from deephunter.methodology.packs.base import (
    MethodologyPack, PackCategory, PackChecklist, PackPlannerRule,
)
from deephunter.methodology.packs.registry import register_pack
from deephunter.core.types import BugClass

pack = MethodologyPack(
    name="My Framework",
    version="1.0.0",
    category=PackCategory.FRAMEWORK,
    supported_technologies=["My Framework"],
    checklists=[
        PackChecklist(
            objective="Test auth bypass",
            procedure="1. Test endpoint without token\n2. Verify access",
            priority="critical",
            difficulty="medium",
            bug_classes=[BugClass.AUTH_BYPASS],
        ),
    ],
    planner_rules=[
        PackPlannerRule(
            technology="My Framework",
            description="Prioritize auth testing",
            priority_modifier=0.2,
            phase="authentication_analysis",
        ),
    ],
)
register_pack(pack)
```

## Validation

Packs are validated on registration:

- Name and version are required
- At least one supported technology, framework, or attack surface area
- All checklist items must have objectives and valid priorities
- Planner rules must have descriptions and valid priority modifiers

## Testing

```bash
python -m pytest tests/unit/test_methodology_packs.py -v
```

Coverage: Base models, registry, pack loading, content verification, decision
tree structure, planner integration, framework profiles.

## Future

The pack system is designed to scale to:

- 500+ technologies
- 100+ frameworks
- 1000+ investigation workflows
- 5000+ checklist items
- Thousands of planner rules

To add new packs, create a Python file in `framework/` or `cross_cutting/`
exporting a `PACK = MethodologyPack(...)` constant, then register it in
`registry.py`.
