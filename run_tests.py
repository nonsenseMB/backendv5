#!/usr/bin/env python3
"""Test runner with different test suites."""
import sys
import subprocess


def run_tests(test_type="all"):
    """Run tests based on type."""
    commands = {
        "unit": "pytest -m unit -v",
        "integration": "pytest -m integration -v",
        "security": "pytest -m security -v",
        "fast": "pytest -m 'not slow' -v",
        "all": "pytest -v",
        "coverage": "pytest --cov --cov-report=html",
        "parallel": "pytest -n auto -v",
    }

    cmd = commands.get(test_type, commands["all"])
    return subprocess.call(cmd.split())


if __name__ == "__main__":
    test_type = sys.argv[1] if len(sys.argv) > 1 else "all"
    sys.exit(run_tests(test_type))