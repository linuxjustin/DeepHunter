# DeepHunter Architecture

## Overview

```
┌─────────────────────────────────────────────────────────┐
│                        CLI                               │
│              (click + rich)                              │
└──────┬────────────────────────────────────────┬──────────┘
       │                                        │
       ▼                                        ▼
┌──────────────┐  ┌──────────┐  ┌──────────────────────┐
│   Knowledge  │  │   RAG    │  │    Agent              │
│   Engine     │  │  Engine  │  │    Orchestrator       │
│              │  │          │  │                      │
│  ┌────────┐  │  │ ┌──────┐ │  │ ┌────┐ ┌────┐ ┌────┐│
│  │ Store  │  │  │ │Embed │ │  │ │A1  │ │A2  │ │A3  ││
│  │(JSON)  │  │  │ │Retr  │ │  │ └────┘ └────┘ └────┘│
│  └────────┘  │  │ └──────┘ │  └──────────────────────┘
└──────────────┘  └──────────┘
       ▲                ▲              ▲
       │                │              │
┌──────┴────────┐       │              │
│   Ingestion   │       │              │
│   Pipeline    │       │              │
│  ┌──────────┐ │       │              │
│  │ Parsers  │ │       │              │
│  │ MD/HTML/ │ │       │              │
│  │ JSON/YAML│ │       │              │
│  │ PDF      │ │       │              │
│  └──────────┘ │       │              │
└───────────────┘       │              │
                        │              │
                        ▼              ▼
               ┌──────────────────────────┐
               │     Reasoning Engine      │
               │   (Hypothesis Generator)  │
               └──────────────────────────┘
                        │
                        ▼
               ┌──────────────────────────┐
               │    Evaluation Framework   │
               │  (Precision, Recall, F1)  │
               └──────────────────────────┘
                        │
                        ▼
               ┌──────────────────────────┐
               │    Dataset Builder        │
               │   (Training Samples)      │
               └──────────────────────────┘
```

## Data Flow

1. **Documents** (`.md`, `.html`, `.json`, `.yaml`, `.pdf`) are placed in knowledge directories
2. **Parsers** extract plain text and sections from each document
3. **Metadata Extractor** heuristically detects technologies, bug classes, and cloud providers
4. **Ingestion Pipeline** builds a `SecurityKnowledgeObject` (SKO) and stores it
5. **Knowledge Store** persists SKOs to JSON and provides search/retrieval
6. **RAG Engine** indexes SKO content as embedding vectors for similarity search
7. **Reasoning Engine** uses retrieved SKOs to generate ranked investigation hypotheses
8. **Dataset Builder** converts SKOs and hypotheses into training samples
9. **Evaluation Framework** measures retrieval and reasoning quality against ground truth

## SKO Data Model

Every document becomes a `SecurityKnowledgeObject` with:

- Identification: `id`, `title`, `source`, `source_type`
- Classification: `tags`, `technology`, `framework`, `bug_classes`, `cloud_provider`
- Analysis: `authentication`, `trust_boundaries`, `interesting_headers`, `interesting_parameters`
- Relationships: `related_writeups`, `related_cves`, `references`
- Testing: `high_level_testing_ideas`
- Provenance: `created`, `updated`, `confidence`, `author`

## Extensibility

- **New parsers**: Implement the `Parser` ABC and register with `ParserRegistry`
- **New embedding providers**: Implement the `EmbeddingProvider` ABC
- **New agents**: Implement the `Agent` ABC and register with `AgentRegistry`
- **New metrics**: Extend the `Evaluator` class