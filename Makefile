.PHONY: install dev install-dev lint format typecheck test test-cov clean build

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,full]"

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

typecheck:
	mypy src/

test:
	pytest tests/unit/ tests/integration/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-cov:
	pytest tests/unit/ tests/integration/ --cov=deephunter --cov-report=term-missing

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .coverage htmlcov/

build:
	python -m build