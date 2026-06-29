# Knowledge Ingestion Engine v1

## Architecture

The ingestion engine is designed as a series of independent, testable stages
connected by an event bus.  Each stage has a single responsibility and can be
replaced or extended without affecting the others.

```
                    ┌─────────────────────────────────────────┐
                    │              EventBus                    │
                    │  subscribe / emit typed events           │
                    └──┬──────┬──────┬──────┬──────┬──────┬───┘
                       │      │      │      │      │      │
  ┌──────────┐    ┌───▼──┐ ┌─▼───┐ ┌▼────┐ ┌▼────┐ ┌▼────┐ ┌▼────────┐
  │Discovery │───▶│Parse │─▶│Meta │─▶│Norm │─▶│Vali-│─▶│Dedup│─▶│Storage  │
  │          │    │      │  │Extr │  │     │  │date │  │     │  │         │
  └──────────┘    └──────┘  └─────┘  └─────┘  └─────┘  └─────┘  └─────────┘
```

### Stages

| Stage | File | Responsibility |
|-------|------|----------------|
| **Discovery** | `discovery.py` | Finds files (single, directory, recursive). Filters by extension and size. |
| **Parsing** | `parsers/*.py` | Routes each file to the appropriate parser via `ParserRegistry`. |
| **Metadata Extraction** | `extractor.py` | Heuristic detection of technologies, bug classes, cloud providers, frameworks, programming languages, OS, tags, author, title. |
| **Normalization** | `normalizer.py` | Normalizes line endings, strips whitespace, collapses blank lines. Produces `normalized_content` for dedup. |
| **Validation** | `validator.py` | Validates every SKO using Pydantic schema. Collects failures into a `ValidationReport`. Never crashes the pipeline. |
| **Deduplication** | `dedup.py` | Pluggable strategies (content hash SHA-256, no-op). Extensible for semantic similarity. |
| **Storage** | `store.py` / `json_store.py` | Configurable backend: SQLite or individual JSON files. |

## Event Bus

The `EventBus` emits typed events at every stage.  Modules can subscribe
to specific event types:

```python
from deephunter.ingestion.events import EventBus, SKOCreatedEvent

bus = EventBus()
bus.subscribe(SKOCreatedEvent, lambda e: print(f"Created SKO {e.sko.id}"))
```

### Event types

| Event | Emitted when |
|-------|-------------|
| `DocumentDiscoveredEvent` | A file is found by the discoverer |
| `DocumentSkippedEvent` | A file is skipped (no parser, too large) |
| `ParseStartedEvent` | Before a document is parsed |
| `ParseCompletedEvent` | After successful parsing |
| `ParseFailedEvent` | When parsing fails |
| `MetadataExtractedEvent` | After metadata extraction completes |
| `SKOCreatedEvent` | After an SKO is constructed |
| `ValidationFailedEvent` | When an SKO fails validation |
| `DuplicateSkippedEvent` | When a duplicate is detected and skipped |
| `DocumentStoredEvent` | After an SKO is persisted |
| `IngestionCompleteEvent` | At the end of the entire pipeline run |

## Usage

### Basic ingestion

```python
from deephunter.core.config import DeepHunterConfig
from deephunter.ingestion.pipeline import IngestionPipeline
from deephunter.knowledge.store import KnowledgeStore

config = DeepHunterConfig.default()
store = KnowledgeStore()

pipeline = IngestionPipeline(config, store)
report = pipeline.run(paths=["docs/"])
print(f"Stored {report.stored} SKOs in {report.elapsed_seconds:.2f}s")
```

### CLI

```bash
# Ingest a directory
deephunter ingest docs/

# Ingest multiple paths
deephunter ingest notes.md docs/

# Non-recursive
deephunter ingest docs/ --no-recursive

# JSON output
deephunter ingest docs/ --format json
```

## Configuration

New configuration sections added to `config.yaml`:

```yaml
ingestion:
  discovery:
    recursive: true
    follow_symlinks: false
    exclude_patterns: []
  dedup:
    enabled: true
    strategy: content_hash
    require_all: false
  storage:
    backend: sqlite          # "sqlite" or "json"
    json_path: ./knowledge/skos
    sqlite_path: null         # null = default ~/.deephunter/store.db
```

## Deduplication

The deduplication system uses a strategy pattern:

```python
from deephunter.ingestion.dedup import (
    ContentHashDedup,
    DeduplicationEngine,
)

engine = DeduplicationEngine(strategies=[ContentHashDedup()])
pipeline = IngestionPipeline(config, store, dedup_engine=engine)
```

**`ContentHashDedup`** computes SHA-256 of `normalized_content` (falling back to `raw_content`). Two SKOs with identical content are flagged as duplicates.

**`NoOpDedup`** never flags duplicates (used when dedup is disabled).

To add a new strategy, implement `DeduplicationStrategy`:

```python
from deephunter.ingestion.dedup import DeduplicationStrategy, DedupResult

class SemanticDedup(DeduplicationStrategy):
    def is_duplicate(self, sko, store) -> DedupResult:
        # ... implementation ...
        return DedupResult(is_duplicate=True, strategy="semantic")
```

## Validation

Validation uses Pydantic's schema validation but collects errors
into a `ValidationReport` instead of raising:

```python
from deephunter.ingestion.validator import SKOValidator

valid, errors = SKOValidator.validate_and_report(sko)
if not valid:
    print(f"Validation failed: {errors}")
```

## Metadata Extraction

The `MetadataExtractor` has been enhanced with new extractors:

| Method | Returns | What it detects |
|--------|---------|-----------------|
| `extract_technologies()` | `list[Technology]` | Node.js, React, Django, etc. |
| `extract_bug_classes()` | `list[BugClass]` | SQL injection, XSS, CSRF, etc. |
| `extract_cloud_providers()` | `list[CloudProvider]` | AWS, Azure, GCP |
| `extract_frameworks()` | `list[Framework]` | OWASP ASVS, MITRE ATT&CK, NIST |
| `extract_programming_languages()` | `list[str]` | Python, Go, Rust, Java, etc. |
| `extract_operating_systems()` | `list[str]` | Linux, Windows, macOS, etc. |
| `extract_tags()` | `list[str]` | authentication, api-security, cloud |
| `extract_title()` | `str \| None` | From H1, `<title>`, or first line |
| `extract_author()` | `str \| None` | From `Author:`, `By:` markers |

## Storage Backends

### SQLite (default)

The `KnowledgeStore` persists SKOs to a SQLite database with full-text
search and tag indexing.

### JSON files

The `JSONKnowledgeStore` writes each SKO to its own JSON file:

```
knowledge/skos/sko-a1b2c3d4e5f6.json
knowledge/skos/sko-f6e5d4c3b2a1.json
```

Configure via `--backend json` or config:

```yaml
ingestion:
  storage:
    backend: json
    json_path: ./knowledge/skos
```

## Pipeline Report

Every pipeline run returns an `IngestionReport`:

```python
@dataclass
class IngestionReport:
    total: int              # Files discovered
    parsed: int             # Successfully parsed
    stored: int             # Stored as SKOs
    skipped: int            # Skipped (no parser, etc.)
    duplicates: int         # Deduplicated
    failed: int             # Failed to process
    elapsed_seconds: float   # Wall-clock time
    validation: ValidationReport  # Per-SKO validation results
    errors: list[FileResult]      # Per-file error details
```

## Extension Points

1. **New parser**: implement `Parser` ABC, register via `ParserRegistry.register()`.
2. **New dedup strategy**: implement `DeduplicationStrategy`, pass to `DeduplicationEngine`.
3. **New event handler**: `event_bus.subscribe(EventType, handler)`.
4. **New storage backend**: implement the same CRUD interface as `KnowledgeStore` / `JSONKnowledgeStore`.
5. **New metadata extractor**: add a method to `MetadataExtractor`.

## File Tree

```
src/deephunter/
├── ingestion/
│   ├── __init__.py        # Exports all public classes
│   ├── pipeline.py        # Stage-based IngestionPipeline
│   ├── discovery.py       # FileDiscoverer
│   ├── dedup.py           # Deduplication strategies
│   ├── events.py          # EventBus + typed events
│   ├── extractor.py       # Enhanced metadata extraction
│   ├── normalizer.py      # ContentNormalizer
│   └── validator.py       # SKOValidator + ValidationReport
├── knowledge/
│   ├── store.py           # SQLite KnowledgeStore
│   └── json_store.py      # JSON-file-backed KnowledgeStore
├── core/
│   └── config.py          # DiscoveryConfig, DedupConfig, StorageConfig
└── cli/
    └── main.py            # Rich progress bars, --format, --recursive
tests/
├── unit/
│   ├── test_ingestion_discovery.py
│   ├── test_ingestion_events.py
│   ├── test_ingestion_dedup.py
│   ├── test_ingestion_validator.py
│   ├── test_ingestion_normalizer.py
│   ├── test_ingestion_extractor.py
│   ├── test_ingestion_pipeline.py
│   └── test_knowledge_json_store.py
└── integration/
    └── test_ingestion_v2.py
```
