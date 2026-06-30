# SKO v1 — Security Knowledge Object Schema

## Purpose

The Security Knowledge Object (SKO) is the core data primitive of DeepHunter. Every
ingested document is parsed into a structured SKO with typed fields for classification,
relationships, provenance tracking, and testing guidance metadata.  v1 extends the
original model with nested types, richer classification, and formal versioning support.

## Schema versioning

| `schema_version` | Description            |
|------------------|------------------------|
| 1                | Initial stable schema  |

The `schema_version` field is an integer ≥ 1.  It is set automatically by the library
but can be overridden when constructing an SKO.  Consumers should assert a minimum
supported version when reading SKOs from storage.

### Migration rules

- **Adding a field**: always provide a default so old SKOs deserialize cleanly.
- **Removing a field**: add a `model_validator` that strips the field on load.
- **Changing a field type**: increment `schema_version` and add a migration path.

New fields in v1 all have defaults (empty list, `None`, or `""`), so v0 SKOs
can be loaded by v1 code without changes.

## Field reference

### Identity & versioning

| Field             | Type   | Default                                      | Description                         |
|-------------------|--------|----------------------------------------------|-------------------------------------|
| `id`              | `str`  | `sko-<uuid4().hex[:12]>`                     | Unique identifier — regex `sko-[a-f0-9]{12}` |
| `schema_version`  | `int`  | `1`                                          | Schema version for migration support |

### Core content

| Field         | Type     | Default | Description                                   |
|---------------|----------|---------|-----------------------------------------------|
| `title`       | `str`    | *(required, non-empty)* | Human-readable title            |
| `summary`     | `str`    | `""`    | Brief summary of the content                  |
| `description` | `str`    | `""`    | Full description or analysis (longer than summary) |

### Provenance

| Field          | Type                    | Default          | Description                      |
|----------------|-------------------------|------------------|----------------------------------|
| `source`       | `str`                   | *(required, valid URL or absolute path)* | Original source |
| `source_type`  | `SourceType`            | `SourceType.OTHER` | Source classification          |
| `document_type`| `DocumentType`          | `DocumentType.UNKNOWN` | Format of the source document |
| `author`       | `str \| None`           | `None`           | Original author or publisher      |
| `created_at`   | `datetime`              | `now(UTC)`       | When this SKO was created         |
| `updated_at`   | `datetime`              | `now(UTC)`       | When this SKO was last updated    |

### Classification

| Field                | Type            | Default | Description                       |
|----------------------|-----------------|---------|-----------------------------------|
| `tags`               | `list[str]`     | `[]`    | Free-form tags                    |
| `technology`         | `list[Technology]` | `[]` | Technologies detected           |
| `framework`          | `list[Framework]`  | `[]` | Security or dev frameworks     |
| `programming_language` | `list[str]`   | `[]`    | Languages mentioned               |
| `operating_system`   | `list[str]`     | `[]`    | Operating systems targeted        |
| `cloud_provider`     | `list[CloudProvider]` | `[]` | Cloud providers referenced     |

### Vulnerability classification

| Field         | Type            | Default | Description                         |
|---------------|-----------------|---------|-------------------------------------|
| `bug_classes` | `list[BugClass]` | `[]`  | Detected bug classes (e.g. SQL injection) |

### Authentication & authorization

| Field           | Type                    | Default | Description                              |
|-----------------|-------------------------|---------|------------------------------------------|
| `authentication`| `list[AuthMechanism]`   | `[]`    | Authentication mechanisms discussed      |
| `authorization` | `list[AuthorizationModel]` | `[]` | Authorization models or checks described |

### Architecture analysis

| Field             | Type                          | Default | Description                           |
|-------------------|-------------------------------|---------|---------------------------------------|
| `business_logic`  | `list[BusinessLogicConcern]`  | `[]`    | Business logic concerns or flaws      |
| `attack_surface`  | `list[AttackSurfaceEntry]`    | `[]`    | Attack surface entry points           |
| `trust_boundaries`| `list[TrustBoundary]`         | `[]`    | Trust boundaries in the application   |

### Interesting findings

| Field                   | Type        | Default | Description                     |
|-------------------------|-------------|---------|---------------------------------|
| `interesting_headers`   | `list[str]` | `[]`    | Notable HTTP headers            |
| `interesting_parameters`| `list[str]` | `[]`    | Notable request parameters      |
| `interesting_endpoints` | `list[str]` | `[]`    | Notable API endpoints or routes |

### Testing guidance

| Field                    | Type                               | Default | Description                             |
|--------------------------|------------------------------------|---------|-----------------------------------------|
| `high_level_testing_ideas` | `list[TestChecklistItem]`       | `[]`    | High-level testing ideas                |
| `manual_test_checklist`  | `list[ManualTestChecklistItem]`    | `[]`    | Step-by-step manual test checklist      |
| `payload_references`     | `list[PayloadReference]`           | `[]`    | Specific payload strings for testing    |

### Relationships

| Field              | Type                       | Default | Description                        |
|--------------------|----------------------------|---------|------------------------------------|
| `related_cves`     | `list[RelatedReference]`   | `[]`    | Related CVE entries                |
| `related_cwes`     | `list[str]`                | `[]`    | Related CWE IDs (e.g. `"CWE-79"`) |
| `related_writeups` | `list[RelatedReference]`   | `[]`    | Related writeups or blog posts     |
| `related_frameworks`| `list[Framework]`         | `[]`    | Related security frameworks        |
| `references`       | `list[RelatedReference]`   | `[]`    | General references                 |

### Confidence

| Field        | Type         | Default                  | Description                               |
|--------------|--------------|--------------------------|-------------------------------------------|
| `confidence` | `Confidence` | `Confidence.UNKNOWN`     | Confidence in accuracy and relevance      |

### Raw & processed content

| Field               | Type             | Default | Description                                  |
|---------------------|------------------|---------|----------------------------------------------|
| `raw_content`       | `str \| None`    | `None`  | Original document text (for RAG embedding)   |
| `normalized_content`| `str \| None`   | `None`  | Cleaned version of raw_content for dedup     |

### Extensible metadata

| Field      | Type               | Default | Description                            |
|------------|--------------------|---------|----------------------------------------|
| `metadata` | `list[Metadata]`   | `[]`    | Key-value metadata for future fields   |

## Nested models

All nested models are defined in `deephunter/core/types.py`.

### `AttackSurfaceEntry`

An attack surface entry point in the target application.

| Field                   | Type        | Default  | Description                        |
|-------------------------|-------------|----------|------------------------------------|
| `name`                  | `str`       | *(required)* | Human-readable name            |
| `description`           | `str`       | `""`     | What this entry point does         |
| `protocol`              | `str`       | `"https"`| Protocol (http, https, ws, etc.)   |
| `method`                | `str`       | `""`     | HTTP method (GET, POST, etc.)      |
| `path`                  | `str`       | `""`     | URL path pattern                   |
| `parameters`            | `list[str]` | `[]`     | Parameters accepted                |
| `authentication_required` | `bool`    | `True`   | Whether auth is required           |
| `authorization_required`  | `bool`    | `True`   | Whether authorization is required  |
| `bug_classes`           | `list[str]` | `[]`     | Bug classes relevant to this entry |

### `BusinessLogicConcern`

A business logic concern or flaw pattern.

| Field                    | Type    | Default    | Description                          |
|--------------------------|---------|------------|--------------------------------------|
| `description`            | `str`   | *(required)* | What the business logic does       |
| `impact`                 | `str`   | `""`       | Potential security impact            |
| `attack_scenario`        | `str`   | `""`       | How this could be exploited          |
| `complexity`             | `str`   | `"medium"` | low, medium, high                    |
| `requires_authentication`| `bool`  | `True`     | Whether authentication is needed     |

### `AuthorizationModel`

Describes an authorization check or model.

| Field              | Type        | Default | Description                           |
|--------------------|-------------|---------|---------------------------------------|
| `model_type`       | `str`       | *(required)* | Type (RBAC, ABAC, ACL, ownership) |
| `description`      | `str`       | `""`    | How authorization works               |
| `roles`            | `list[str]` | `[]`    | Relevant roles                        |
| `permissions`      | `list[str]` | `[]`    | Relevant permissions                  |
| `bypass_scenarios` | `list[str]` | `[]`    | Known or theorised bypass scenarios   |

### `ManualTestChecklistItem`

A single manual test step.

| Field             | Type        | Default | Description                          |
|-------------------|-------------|---------|--------------------------------------|
| `step_id`         | `str`       | `""`    | Checklist item identifier            |
| `category`        | `str`       | `""`    | Category (Authentication, Input Validation, etc.) |
| `description`     | `str`       | *(required)* | What to test                     |
| `expected_result` | `str`       | `""`    | What a successful test looks like    |
| `tools`           | `list[str]` | `[]`    | Recommended tools                    |
| `references`      | `list[str]` | `[]`    | Reference URLs or IDs                |

### `PayloadReference`

A reference to a specific payload.

| Field          | Type        | Default     | Description                          |
|----------------|-------------|-------------|--------------------------------------|
| `payload`      | `str`       | *(required)* | The actual payload string            |
| `description`  | `str`       | `""`        | What this payload tests              |
| `bug_classes`  | `list[str]` | `[]`        | Bug classes this payload targets     |
| `source`       | `str`       | `""`        | Where this payload was found         |
| `encoding`     | `str`       | `"raw"`     | Encoding: raw, url, base64, etc.     |
| `effectiveness`| `str`       | `"unknown"` | How often it works: low, medium, high, unknown |

## Validators

The model enforces the following constraints:

| Field             | Constraint                                                    |
|-------------------|---------------------------------------------------------------|
| `title`           | Must not be empty (after stripping whitespace)                |
| `source`          | Must be a valid URL (`http://`, `https://`) or absolute path  |
| `id`              | Must match regex `^sko-[a-f0-9]{12}$`                         |
| `related_cwes`    | Each entry must match `CWE-<number>`                         |
| `schema_version`  | Must be ≥ 1                                                   |
| `updated_at`      | Automatically set to `now(UTC)` on validation                 |

## Parser guide

When writing a parser, create a `SecurityKnowledgeObject` and populate as many fields
as the source document supports.  All v1 fields accept defaults, so you only need to
set fields for which you have data:

```python
from deephunter.knowledge.models import SecurityKnowledgeObject

sko = SecurityKnowledgeObject(
    title="SQLi in GraphQL",
    source="https://example.com/graphql-sqli",
    source_type=SourceType.WRITEUP,
    bug_classes=[BugClass.SQL_INJECTION],
    programming_language=["Python", "JavaScript"],
    interesting_endpoints=["/graphql"],
    payload_references=[
        PayloadReference(
            payload="' OR 1=1 --",
            description="Basic SQLi bypass for GraphQL",
        ),
    ],
)
```

## Consumer guide

Consumers should always check `schema_version` before processing:

```python
from deephunter.knowledge.models import SecurityKnowledgeObject

MIN_SUPPORTED = 1

def process_sko(data: dict) -> None:
    sko = SecurityKnowledgeObject.from_dict(data)
    if sko.schema_version < MIN_SUPPORTED:
        raise ValueError(f"SKO schema v{sko.schema_version} not supported")
    # Safe to access v1 fields — they have defaults if absent
    for endpoint in sko.interesting_endpoints:
        print(f"Found endpoint: {endpoint}")
```

### Backward compatibility

All v1 fields have defaults, so v0 SKOs (which are essentially v1 with all
defaults) load without error.  The only breaking change is the `source` validator,
which now rejects strings that are not valid URLs or absolute paths.  If you have
existing data with bare filenames, prepend a path prefix.

## Storage

The `KnowledgeStore` persists all v1 fields in SQLite.  New columns are added via
`ALTER TABLE` migration when the store is first opened, so existing databases
continue to work.  See `deephunter/knowledge/store.py` for the full schema.
Columns storing list or dict values use JSON encoding.
