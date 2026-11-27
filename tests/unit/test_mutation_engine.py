"""Unit tests for the in-tree AST mutation testing engine."""

import ast
from pathlib import Path

import pytest

from tests.mutation.run_mutation_tests import TARGETS, MutationFinder, Mutator

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.tier0
def test_mutation_targets_exist():
    """Verify all mutation targets resolve to existing files and test suites."""
    for name, config in TARGETS.items():
        assert config["file"].exists(), f"Target file for {name} does not exist: {config['file']}"
        test_file = REPO_ROOT / config["test"]
        assert test_file.exists(), f"Test suite for {name} does not exist: {test_file}"


@pytest.mark.tier0
def test_mutation_finder_discovers_operators():
    """Verify MutationFinder discovers comparison and boolean operators."""
    sample_code = """
def is_valid(x: int, flag: bool = True) -> bool:
    if x == 10:
        return True
    if x != 20:
        return False
    if "admin" in ["user", "admin"]:
        return flag
    if 5 not in [1, 2]:
        return False
    return False
"""
    tree = ast.parse(sample_code)
    finder = MutationFinder()
    finder.visit(tree)

    types = [m[2] for m in finder.mutations]
    assert "Eq->NotEq" in types
    assert "NotEq->Eq" in types
    assert "In->NotIn" in types
    assert "NotIn->In" in types
    assert "Bool(True->False)" in types
    assert "Bool(False->True)" in types


@pytest.mark.tier0
def test_mutator_transforms_ast_correctly():
    """Verify Mutator generates valid mutated AST without breaking syntax."""
    sample_code = "def check(a):\n    return a == 42\n"
    tree = ast.parse(sample_code)
    finder = MutationFinder()
    finder.visit(tree)
    assert len(finder.mutations) == 1
    target_line, target_col, mutation_type = finder.mutations[0]

    mutator = Mutator(target_line, target_col, mutation_type)
    mutated_tree = mutator.visit(tree)
    ast.fix_missing_locations(mutated_tree)

    mutated_code = ast.unparse(mutated_tree)
    assert "a != 42" in mutated_code
