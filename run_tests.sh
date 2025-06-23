#!/bin/bash
# Test runner script for Backend v5

set -e

echo "🧪 Running Backend v5 Test Suite"
echo "================================"

# Check if poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "❌ Poetry is not installed. Please install Poetry first."
    exit 1
fi

# Install dependencies if needed
echo "📦 Checking dependencies..."
poetry install --quiet

# Run tests based on argument
case "${1:-all}" in
    "unit")
        echo "🔬 Running Unit Tests..."
        poetry run pytest tests/unit/ -v
        ;;
    "integration")
        echo "🔗 Running Integration Tests..."
        poetry run pytest tests/integration/ -v
        ;;
    "e2e")
        echo "🌐 Running End-to-End Tests..."
        poetry run pytest tests/e2e/ -v
        ;;
    "load")
        echo "⚡ Running Load Tests..."
        poetry run pytest tests/load/ -v
        ;;
    "benchmark")
        echo "📊 Running Benchmarks..."
        poetry run pytest tests/benchmarks/ -v
        ;;
    "coverage")
        echo "📈 Running Tests with Coverage..."
        poetry run pytest --cov=src --cov-report=term-missing --cov-report=html
        echo "Coverage report generated in htmlcov/index.html"
        ;;
    "quick")
        echo "⚡ Running Quick Tests (excluding load/benchmarks)..."
        poetry run pytest tests/unit/ tests/integration/ tests/e2e/ -v
        ;;
    "all")
        echo "🚀 Running All Tests..."
        poetry run pytest -v
        ;;
    *)
        echo "Usage: $0 [unit|integration|e2e|load|benchmark|coverage|quick|all]"
        echo ""
        echo "Options:"
        echo "  unit        - Run unit tests only"
        echo "  integration - Run integration tests only"
        echo "  e2e         - Run end-to-end tests only"
        echo "  load        - Run load tests only"
        echo "  benchmark   - Run benchmark tests only"
        echo "  coverage    - Run all tests with coverage report"
        echo "  quick       - Run all tests except load/benchmarks"
        echo "  all         - Run all tests (default)"
        exit 1
        ;;
esac

echo ""
echo "✅ Tests completed!"