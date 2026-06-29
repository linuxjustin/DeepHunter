# DeepHunter Project Overview

## Mission

DeepHunter is a modular AI-assisted bug bounty research platform designed to help experienced security researchers:
- Organize security knowledge from multiple sources
- Retrieve relevant references during investigations
- Generate structured investigation hypotheses
- Suggest testing strategies based on known patterns
- Produce structured reports and datasets

## Non-Goals

- **Not** an autonomous vulnerability scanner
- **Not** a chatbot
- **Not** a replacement for skilled security researchers
- **Not** a magic "find bugs" button

## Architecture Principles

- **Modular** — Each module has a single responsibility and a clean interface
- **Offline-first** — Core functionality works without internet or API keys
- **Pluggable** — Parsers, embedding providers, and agents are extensible
- **Testable** — Every module has comprehensive unit tests
- **Type-safe** — Full Python 3.12 type hints throughout

## Module Dependencies

```
utils  →  (no internal dependencies)
core   →  utils
knowledge  →  core
parsers  →  core
ingestion  →  core, knowledge, parsers, utils
rag  →  core, knowledge, utils
reasoning  →  core, knowledge, rag, utils
agents  →  core, utils
evaluation  →  core, utils
training  →  core, knowledge, reasoning, utils
cli  →  all modules
```

No circular dependencies exist in the architecture.

## Configuration

Configuration is managed via YAML/JSON files using Pydantic models. Default configuration is created with `deephunter init`.

See `deephunter.core.config.DeepHunterConfig` for all available settings.