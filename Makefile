.PHONY: help install dev-install test test-unit test-integration test-security test-coverage test-watch test-parallel lint format type-check clean run migrate

help:
	@echo "Available commands:"
	@echo "  make install           - Install production dependencies"
	@echo "  make dev-install       - Install all dependencies including dev"
	@echo "  make test              - Run all tests"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-integration  - Run integration tests only"
	@echo "  make test-security     - Run security tests only"
	@echo "  make test-coverage     - Run tests with coverage report"
	@echo "  make test-watch        - Run tests in watch mode"
	@echo "  make test-parallel     - Run tests in parallel"
	@echo "  make lint              - Run linter"
	@echo "  make format            - Format code"
	@echo "  make type-check        - Run type checker"
	@echo "  make clean             - Clean cache files"
	@echo "  make run               - Run the application"
	@echo "  make migrate           - Run database migrations"

install:
	poetry install --no-dev

dev-install:
	poetry install

test:
	@python run_tests.py all

test-unit:
	@python run_tests.py unit

test-integration:
	@python run_tests.py integration

test-security:
	@python run_tests.py security

test-coverage:
	@python run_tests.py coverage
	@echo "Opening coverage report..."
	@open htmlcov/index.html

test-watch:
	@poetry run ptw -- -v

test-parallel:
	@python run_tests.py parallel

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