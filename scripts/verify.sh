#!/usr/bin/env bash
# ==============================================================================
# Ether Mechanical Verification Script
# ==============================================================================
# Runs AST invariants, property-based tests, schema registry checks, and ruff.

set -eo pipefail

PYTHON_BIN="python3"
if [ -f ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
fi

PYTEST_BIN="pytest"
if [ -f ".venv/bin/pytest" ]; then
    PYTEST_BIN=".venv/bin/pytest"
fi

RUFF_BIN="ruff"
if [ -f ".venv/bin/ruff" ]; then
    RUFF_BIN=".venv/bin/ruff"
fi

echo "--- [1/4] Code Style & Quality (ruff check & format) ---"
$RUFF_BIN check .
$RUFF_BIN format --check .

echo -e "\n--- [2/4] Schema Registry Synchronization ---"
$PYTHON_BIN scripts/generate_schema_registry.py --check

echo -e "\n--- [3/4] Tier 0 AST Architectural & Mathematical Invariants ---"
$PYTEST_BIN -m tier0 -q

echo -e "\n--- [4/4] Full Regression Test Suite ---"
$PYTEST_BIN tests/

echo -e "\n=============================================="
echo "    ALL ETHER MECHANICAL GATES PASSED [OK]    "
echo "=============================================="
