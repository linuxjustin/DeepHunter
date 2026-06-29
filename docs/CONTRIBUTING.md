# Contributing

## Development Setup

```bash
git clone https://github.com/your-org/deephunter
cd deephunter
python -m venv .venv
source .venv/bin/activate
pip install -e ".[full]"
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Standards

- Python 3.12+
- Type hints everywhere
- Pydantic v2 for data models
- SOLID principles
- Composition over inheritance
- Docstrings on all public functions
- No circular imports
- No global state

## Pull Request Checklist

- [ ] Code follows project architecture
- [ ] Type hints are complete
- [ ] Tests cover happy path and edge cases
- [ ] `pytest tests/` passes
- [ ] No new external dependencies without justification
- [ ] Public functions have docstrings
- [ ] No placeholder code

## Module Guidelines

- Keep modules small and focused
- Use dependency injection for testability
- Separate business logic from I/O
- Raise meaningful exceptions
- Log failures with context