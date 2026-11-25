"""Automated AST architectural guard tests for Ether.

Mechanically enforces invariants:
1. Pure Headless Core: Zero Textual, curses, or UI imports anywhere in src/ether.
2. Layer DAG: Primitives (schemas, common) must never import from higher layers (graph, core, gateway).
3. Process Safety: No raw os.system or shell=True invocations.
"""

import ast
import tomllib
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


@pytest.mark.tier0
def test_complete_unidirectional_layer_dag():
    """Verify that the layer hierarchy strictly obeys a unidirectional downwards DAG.

    Layer Hierarchy (Top to Bottom):
      ether.cli
        ↓
      ether.gateway
        ↓
      ether.core
        ↓
      ether.graph
        ↓
      ether.registry
        ↓
      ether.schemas
        ↓
      ether.common
    """
    dag_rules = {
        "common": [
            "ether.schemas",
            "ether.registry",
            "ether.graph",
            "ether.core",
            "ether.drift",
            "ether.gateway",
            "ether.cli",
            "ether.mcp",
        ],
        "schemas": [
            "ether.registry",
            "ether.graph",
            "ether.core",
            "ether.drift",
            "ether.gateway",
            "ether.cli",
            "ether.mcp",
        ],
        "registry": [
            "ether.graph",
            "ether.core",
            "ether.drift",
            "ether.gateway",
            "ether.cli",
            "ether.mcp",
        ],
        "graph": ["ether.core", "ether.drift", "ether.gateway", "ether.cli", "ether.mcp"],
        "core": ["ether.drift", "ether.gateway", "ether.cli", "ether.mcp"],
        "drift": ["ether.core", "ether.gateway", "ether.cli", "ether.mcp"],
        "gateway": ["ether.drift", "ether.cli", "ether.mcp"],
        "mcp": ["ether.cli"],
        "cli": [],
    }

    violations = []
    for layer, banned in dag_rules.items():
        layer_dir = SRC_ROOT / layer
        if not layer_dir.is_dir():
            continue

        for py_file in _get_python_files(layer_dir):
            with open(py_file, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(py_file))

            for node in ast.walk(tree):
                mod = ""
                if isinstance(node, ast.ImportFrom) and node.module:
                    mod = node.module
                elif isinstance(node, ast.Import):
                    for name in node.names:
                        mod = name.name

                if mod:
                    for b in banned:
                        if mod == b or mod.startswith(b + "."):
                            violations.append(
                                f"[{layer}] {py_file.name}:{node.lineno} imports forbidden higher layer '{mod}'"
                            )

    assert not violations, (
        f"Unidirectional Layer DAG violation: dependencies must flow strictly downwards:\n"
        + "\n".join(violations)
    )


@pytest.mark.tier0
def test_tools_layer_purity():
    """Verify that pluggable tool adapters in tools/ never import from forbidden higher layers."""
    tools_dir = Path(__file__).resolve().parent.parent.parent / "tools"
    violations = []
    banned_in_tools = {"ether.core", "ether.gateway", "ether.cli", "ether.mcp"}

    for py_file in _get_python_files(tools_dir):
        with open(py_file, "r", encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
            except SyntaxError:
                continue

        for node in ast.walk(tree):
            mod = ""
            if isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module
            elif isinstance(node, ast.Import):
                for name in node.names:
                    mod = name.name

            if mod:
                for b in banned_in_tools:
                    if mod == b or mod.startswith(b + "."):
                        violations.append(
                            f"[tools] {py_file.name}:{node.lineno} imports forbidden higher layer '{mod}'"
                        )

    assert not violations, (
        f"Layer DAG violation: Tools in tools/ must never import from higher layers:\n"
        + "\n".join(violations)
    )


@pytest.mark.tier0
def test_all_manifests_declare_target_types():
    """Verify every tools/*/manifest.toml declares input.target_types as a non-empty list."""
    tools_dir = Path(__file__).resolve().parent.parent.parent / "tools"
    missing = []
    for manifest_path in sorted(tools_dir.glob("*/manifest.toml")):
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)
        target_types = data.get("input", {}).get("target_types")
        if not isinstance(target_types, list) or not target_types:
            missing.append(manifest_path.parent.name)

    assert not missing, f"Manifests missing non-empty input.target_types: {missing}"


@pytest.mark.tier0
def test_manifest_and_adapter_execution_tier_match():
    """Verify execution_tier in manifest.toml matches any explicit execution_tier on the adapter class."""
    tools_dir = Path(__file__).resolve().parent.parent.parent / "tools"
    mismatches = []
    for manifest_path in sorted(tools_dir.glob("*/manifest.toml")):
        adapter_path = manifest_path.parent / "adapter.py"
        if not adapter_path.exists():
            continue
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)
        manifest_tier = data.get("meta", {}).get("execution_tier", "subprocess")

        with open(adapter_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(adapter_path))

        adapter_tier = None
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name) and target.id == "execution_tier":
                                if isinstance(stmt.value, ast.Constant) and isinstance(
                                    stmt.value.value, str
                                ):
                                    adapter_tier = stmt.value.value
        if adapter_tier is not None and adapter_tier != manifest_tier:
            mismatches.append(
                f"{manifest_path.parent.name}: manifest={manifest_tier} != adapter={adapter_tier}"
            )

    assert not mismatches, f"execution_tier mismatches:\n" + "\n".join(mismatches)
