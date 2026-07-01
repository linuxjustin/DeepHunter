# DeepHunter

Modular AI-assisted bug bounty research platform for experienced security researchers.

DeepHunter helps you **organize security knowledge**, **retrieve relevant references**, **generate investigation hypotheses**, **suggest testing strategies**, and **produce structured reports**.

> **DeepHunter is NOT an autonomous hacking tool.** It assists skilled researchers — it does not claim to autonomously discover or verify vulnerabilities.

## Features

- **Knowledge Ingestion** — Parse Markdown, HTML, JSON, YAML, and PDF documents into structured Security Knowledge Objects (SKOs)
- **SKO Storage** — Tagged, searchable, persistent knowledge store with JSON export
- **RAG Engine** — Embedding-based retrieval with cosine similarity search
- **Reasoning Engine** — Hypothesis generation from retrieved knowledge, prioritized by confidence
- **Investigation Orchestrator** — End-to-end workflow with interactive review, progress tracking, and session resumption
- **Context Engine** — Builds structured context for AI prompts with token budgeting and deduplication
- **Report Generator** — Comprehensive markdown reports with findings, evidence, and timeline
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

# Run a complete bug bounty investigation
deephunter run --scope scope.txt --profile bugbounty --provider claude

# Resume a paused investigation
deephunter run --scope scope.txt --resume --session session.json

# Ingest knowledge documents
deephunter ingest knowledge/hacktricks/

# Search knowledge
deephunter search "JWT authentication bypass"

# Generate hypotheses
deephunter hypothesize "Node.js API with JWT authentication"

# List available profiles
deephunter config profiles
```

## Primary Workflow

```bash
# Create scope file (scope.txt)
# example.com
# *.api.example.com

# Run investigation
deephunter run --scope scope.txt --profile bugbounty --provider claude
```

The `run` command orchestrates:
1. Scope validation and normalization
2. Attack surface graph building
3. Technology detection
4. Knowledge and methodology pack selection
5. Investigation planning
6. **Interactive review** (waits for confirmation before active testing)
7. Task execution
8. Evidence collection
9. Report generation

## CLI Commands

| Command | Description |
|---------|-------------|
| `deephunter run` | Run complete investigation workflow |
| `deephunter ingest` | Ingest knowledge documents |
| `deephunter search` | RAG-based knowledge search |
| `deephunter hypothesize` | Generate investigation hypotheses |
| `deephunter plan` | Generate investigation plan |
| `deephunter roadmap` | Detailed investigation roadmap |
| `deephunter report` | Generate bug bounty report |
| `deephunter project create` | Create new project |
| `deephunter workspace list` | List workspace projects |
| `deephunter investigate run` | Run investigation workflow |
| `deephunter investigate resume` | Resume paused investigation |
| `deephunter investigate status` | Check investigation status |
| `deephunter config show` | Show current configuration |
| `deephunter config profiles` | List available profiles |

## Documentation

See [docs/PROJECT.md](docs/PROJECT.md) for the project overview and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the architecture.

## Modules

| Module | Description |
|---|---|
| `core` | Configuration, exceptions, base types |
| `knowledge` | SKO models, builder, and knowledge store |
| `knowledge/packs` | 35+ technology knowledge packs |
| `parsers` | Document parsers (Markdown, HTML, JSON, YAML, PDF) |
| `ingestion` | Pipeline orchestration and metadata extraction |
| `rag` | Embedding providers and similarity retriever |
| `reasoning` | Hypothesis generation engine |
| `agents` | Agent framework and orchestrator |
| `investigation` | Workflow orchestrator, report generator, evidence manager |
| `context` | Context engine with token budgeting |
| `planning` | Investigation planning and prioritization |
| `methodology` | Methodology engine with pack registry |
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