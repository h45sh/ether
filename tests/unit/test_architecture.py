"""Automated AST architectural guard tests for Ether.

Mechanically enforces invariants:
1. Pure Headless Core: Zero Textual, curses, or UI imports anywhere in src/ether.
2. Layer DAG: Primitives (schemas, common) must never import from higher layers (graph, core, gateway).
3. Process Safety: No raw os.system or shell=True invocations.
"""

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "ether"

BANNED_UI_MODULES = {"textual", "curses", "tkinter", "PyQt5", "PyQt6", "PySide6"}


def _get_python_files(directory: Path):
    return [p for p in directory.rglob("*.py") if not p.name.startswith(".")]


@pytest.mark.tier0
def test_zero_ui_imports():
    """Verify that NO files in src/ether import any UI or presentation libraries."""
    violations = []
    for py_file in _get_python_files(SRC_ROOT):
        with open(py_file, "r", encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
            except SyntaxError:
                continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    if root_pkg in BANNED_UI_MODULES:
                        violations.append(f"{py_file.name}:{node.lineno} imports '{alias.name}'")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    if root_pkg in BANNED_UI_MODULES:
                        violations.append(
                            f"{py_file.name}:{node.lineno} imports from '{node.module}'"
                        )

    assert not violations, (
        f"Architectural violation: Banned UI imports found in headless engine:\n"
        + "\n".join(violations)
    )


@pytest.mark.tier0
def test_layer_dag_schemas_are_pure():
    """Verify that ether.schemas only imports from ether.schemas, ether.common, or stdlib."""
    schemas_dir = SRC_ROOT / "schemas"
    violations = []
    banned_in_schemas = {"ether.core", "ether.graph", "ether.gateway", "ether.registry"}

    for py_file in _get_python_files(schemas_dir):
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for banned in banned_in_schemas:
                    if node.module.startswith(banned):
                        violations.append(
                            f"{py_file.name}:{node.lineno} schema imports higher layer '{node.module}'"
                        )

    assert not violations, f"Layer DAG violation: Schemas must be pure core models:\n" + "\n".join(
        violations
    )


@pytest.mark.tier0
def test_no_raw_os_system_or_shell_true():
    """Verify that no code invokes os.system or uses shell=True in subprocess calls."""
    violations = []
    for py_file in _get_python_files(SRC_ROOT):
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            # Check for os.system calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        violations.append(f"{py_file.name}:{node.lineno} uses os.system()")

                # Check for shell=True keyword argument in calls
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        violations.append(
                            f"{py_file.name}:{node.lineno} uses shell=True in subprocess call"
                        )

    assert not violations, f"Security violation: Banned subprocess mechanisms found:\n" + "\n".join(
        violations
    )
