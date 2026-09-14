.PHONY: install test lint format build

install:
	python -m pip install -e '.[dev]'

test:
	python -m pytest -q

lint:
	python -m ruff check src tests integrations
	python -m mypy src

format:
	python -m ruff format src tests integrations

build:
	python -m build
