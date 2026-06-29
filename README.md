# DeepHunter

Modular AI-assisted bug bounty research platform for experienced security researchers.

DeepHunter helps you **organize security knowledge**, **retrieve relevant references**, **generate investigation hypotheses**, **suggest testing strategies**, and **produce structured reports**.

> **DeepHunter is NOT an autonomous hacking tool.** It assists skilled researchers — it does not claim to autonomously discover or verify vulnerabilities.

## Features

- **Knowledge Ingestion** — Parse Markdown, HTML, JSON, YAML, and PDF documents into structured Security Knowledge Objects (SKOs)
- **SKO Storage** — Tagged, searchable, persistent knowledge store with JSON export
- **RAG Engine** — Embedding-based retrieval with cosine similarity search
- **Reasoning Engine** — Hypothesis generation from retrieved knowledge, prioritized by confidence
- **Dataset Builder** — Generate training datasets for fine-tuning security LLMs
- **Evaluation Framework** — Precision, recall, F1, and hit-rate metrics
- **Agent Orchestration** — Multi-agent pipeline for research workflows
- **CLI** — Rich command-line interface for all operations

## Quick Start

```bash
# Install with all extras
pip install deephunter[full]

# Or from source
pip install -e ".[full]"

# Initialize default config
deephunter init

# Ingest knowledge documents
deephunter ingest knowledge/hacktricks/

# Search knowledge
deephunter search "JWT authentication bypass"

# Generate hypotheses
deephunter hypothesize "Node.js API with JWT authentication"
```

## Documentation

See [docs/PROJECT.md](docs/PROJECT.md) for the project overview and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the architecture.

## Modules

| Module | Description |
|---|---|
| `core` | Configuration, exceptions, base types |
| `knowledge` | SKO models, builder, and knowledge store |
| `parsers` | Document parsers (Markdown, HTML, JSON, YAML, PDF) |
| `ingestion` | Pipeline orchestration and metadata extraction |
| `rag` | Embedding providers and similarity retriever |
| `reasoning` | Hypothesis generation engine |
| `agents` | Agent framework and orchestrator |
| `evaluation` | Retrieval and reasoning metrics |
| `training` | Dataset builder for fine-tuning |
| `cli` | Command-line interface |

## Development

```bash
pip install -e ".[full]"
pytest tests/
```

## License

MIT