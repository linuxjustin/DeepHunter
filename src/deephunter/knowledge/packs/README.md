# Knowledge Pack Ecosystem

First-class structured knowledge about 35 technologies, frameworks, protocols, and infrastructure spanning 11 categories. Every pack integrates with every DeepHunter subsystem.

## Directory Structure

```
packs/
├── __init__.py        # Public API re-exports
├── base.py            # Core data models
├── registry.py        # Loader + validator + registry
├── integration.py     # Subsystem adapters (Planner, Reasoning, Context, Prompt, Tech Intel)
├── README.md
├── framework/         # 13 packs: laravel, django, rails, spring_boot, express, fastapi,
│                      #  flask, nextjs, nuxt, nestjs, phoenix, symfony, aspnet
│   └── also:         # 3 CMS packs: wordpress, drupal, magento
├── infrastructure/   # 6 packs: nginx, apache, redis, rabbitmq, kubernetes, docker
├── cloud/            # 4 packs: aws, azure, gcp, cloudflare
├── database/         # 3 packs: postgresql, mysql, mongodb
├── cross_cutting/    # 6 packs: graphql, rest, jwt, oauth, oidc, saml
└── tests/            # Pack test files
```

## Pack Structure (KnowledgePack)

Each pack contains:
- **TechnologyProfile**: name, vendor, language, runtime, aliases, dependencies
- **Components**: 5-8 key components with security relevance ratings (high/medium/low) and vulnerability lists
- **AttackSurfaceProfile**: entry points, endpoints, parameters, auth/authorization info, trust boundaries, 10-12 investigation areas
- **FingerprintProfile**: HTTP headers, cookies, JS indicators, file/directory patterns, error signatures, default paths
- **ReconProfile**: directories, files, endpoints, version detection, debug/admin paths
- **BusinessLogicConcerns**: 3-5 business logic flaws with impact and attack scenarios
- **Relationships**: 5-10 connections to other packs (runs_on, depends_on, integrates_with, etc.)
- **Workflow**: 10-14 step-by-step investigation procedures
- **Checklists**: 5-8 manual test checklist items with expected results and tools
- **References**: OWASP, CVE, vendor documentation links
- **CWE/CVE IDs**: relevant vulnerability classification identifiers

## Subsystem Integration

| Subsystem | Integration Point | Method |
|-----------|------------------|--------|
| **Planner** | KnowledgePackRule (priority 35) | `evaluate(PlannerContext) → InvestigationStep[]` |
| **Reasoning** | KnowledgePackReasoningAdapter | `get_hypotheses_for_tech()` → 605+ hypotheses |
| **Context Engine** | `enrich_context_with_knowledge_packs()` | Returns profiles, signatures, attack surface |
| **Prompt Builder** | `get_prompt_context_enrichment()` | Injects pack metadata into prompts |
| **Tech Intel** | `enrich_tech_intel()` | Fingerprints, relationships, investigation areas |

## Usage

```python
from deephunter.knowledge import load_all_knowledge_packs, get_kp

registry = load_all_knowledge_packs()
laravel = get_kp("laravel")
print(laravel.attack_surface.attack_surface_areas)
print(laravel.relationships)

# Full planning integration ready via RuleRegistry
from deephunter.planning.rules import RuleRegistry
reg = RuleRegistry.with_default_rules()  # includes KnowledgePackRule
```
