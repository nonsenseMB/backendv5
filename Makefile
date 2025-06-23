.PHONY: help install dev-install test lint format type-check clean run migrate

help:
	@echo "Available commands:"
	@echo "  make install       - Install production dependencies"
	@echo "  make dev-install   - Install all dependencies including dev"
	@echo "  make test          - Run tests"
	@echo "  make lint          - Run linter"
	@echo "  make format        - Format code"
	@echo "  make type-check    - Run type checker"
	@echo "  make clean         - Clean cache files"
	@echo "  make run           - Run the application"
	@echo "  make migrate       - Run database migrations"

install:
	poetry install --no-dev

dev-install:
	poetry install

test:
	poetry run pytest

lint:
	poetry run ruff check src tests

format:
	poetry run ruff format src tests

type-check:
	poetry run mypy src

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov

run:
	poetry run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

migrate:
	poetry run alembic upgrade head