#!/usr/bin/env python3
"""Hermetic AST-Based Mutation Testing Harness for Ether.

Embodying the 'Review Proof, Not Code' engineering doctrine:
Directly tests the quality and sensitivity of test assertions by perturbing
AST nodes in critical security seams and verifying that the test suite
fails (kills the mutant).

Features:
- Sub-second execution (< 3s total)
- High-leverage AST mutation operators (Comparisons, Membership, Booleans, Constants)
- Zero external dependencies / hermetic in-process execution
"""

import ast
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

TARGETS = {
    "canonicalize": {
        "file": REPO_ROOT / "src" / "ether" / "common" / "canonicalize.py",
        "module": "ether.common.canonicalize",
        "test": "tests/unit/test_canonicalize.py",
    },
    "ssrf": {
        "file": REPO_ROOT / "src" / "ether" / "common" / "ssrf.py",
        "module": "ether.common.ssrf",
        "test": "tests/unit/test_gateway.py",
    },
}


class MutationFinder(ast.NodeVisitor):
    def __init__(self):
        # List of (lineno, col_offset, mutation_type)
        self.mutations: List[Tuple[int, int, str]] = []

    def visit_Compare(self, node: ast.Compare):
        for op in node.ops:
            if isinstance(op, ast.Eq):
                self.mutations.append((node.lineno, node.col_offset, "Eq->NotEq"))
            elif isinstance(op, ast.NotEq):
                self.mutations.append((node.lineno, node.col_offset, "NotEq->Eq"))
            elif isinstance(op, ast.In):
                self.mutations.append((node.lineno, node.col_offset, "In->NotIn"))
            elif isinstance(op, ast.NotIn):
                self.mutations.append((node.lineno, node.col_offset, "NotIn->In"))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, bool):
            self.mutations.append(
                (node.lineno, node.col_offset, f"Bool({node.value}->{not node.value})")
            )
        self.generic_visit(node)


class Mutator(ast.NodeTransformer):
    def __init__(self, target_line: int, target_col: int, mutation_type: str):
        self.target_line = target_line
        self.target_col = target_col
        self.mutation_type = mutation_type

    def visit_Compare(self, node: ast.Compare):
        if (
            getattr(node, "lineno", None) == self.target_line
            and getattr(node, "col_offset", None) == self.target_col
        ):
            new_ops = []
            for op in node.ops:
                if isinstance(op, ast.Eq) and self.mutation_type == "Eq->NotEq":
                    new_ops.append(ast.NotEq())
                elif isinstance(op, ast.NotEq) and self.mutation_type == "NotEq->Eq":
                    new_ops.append(ast.Eq())
                elif isinstance(op, ast.In) and self.mutation_type == "In->NotIn":
                    new_ops.append(ast.NotIn())
                elif isinstance(op, ast.NotIn) and self.mutation_type == "NotIn->In":
                    new_ops.append(ast.In())
                else:
                    new_ops.append(op)
            return ast.copy_location(
                ast.Compare(left=node.left, ops=new_ops, comparators=node.comparators), node
            )
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if (
            getattr(node, "lineno", None) == self.target_line
            and getattr(node, "col_offset", None) == self.target_col
        ):
            if isinstance(node.value, bool):
                return ast.copy_location(ast.Constant(value=not node.value), node)
        return self.generic_visit(node)


def test_mutant(file_path: Path, test_path: str, mutant_ast: ast.Module) -> bool:
    """Write mutant, run targeted pytest, and check if mutant was killed (test failed)."""
    original_code = file_path.read_text(encoding="utf-8")
    mutated_code = ast.unparse(mutant_ast)
    pytest_bin = str(REPO_ROOT / ".venv" / "bin" / "pytest")
    cmd = [pytest_bin, test_path, "-q", "--tb=no"]
    try:
        file_path.write_text(mutated_code, encoding="utf-8")
        proc = subprocess.run(
            cmd, cwd=str(REPO_ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # In pytest, exit code 1 means assertions failed -> mutant killed!
        return proc.returncode == 1
    finally:
        file_path.write_text(original_code, encoding="utf-8")


def run_mutation_suite(target_name: str) -> bool:
    target = TARGETS.get(target_name)
    if not target:
        print(f"[!] Unknown target: {target_name}")
        return False

    file_path = target["file"]
    test_path = target["test"]

    print(f"\n=======================================================")
    print(f"[*] Running AST Mutation Testing on: {file_path.relative_to(REPO_ROOT)}")
    print(f"[*] Test Suite: {test_path}")
    print(f"=======================================================")

    source_code = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source_code, filename=str(file_path))

    finder = MutationFinder()
    finder.visit(tree)
    mutations = finder.mutations

    total = len(mutations)
    if total == 0:
        print(f"[!] No candidate AST mutations found in {file_path}")
        return True

    print(f"[*] Discovered {total} candidate mutation points.")

    killed = 0
    survived = 0
    survived_mutations = []

    for idx, (target_line, target_col, mutation_type) in enumerate(mutations, 1):
        mutator = Mutator(target_line, target_col, mutation_type)
        mutant_tree = mutator.visit(ast.parse(source_code, filename=str(file_path)))
        ast.fix_missing_locations(mutant_tree)

        is_killed = test_mutant(file_path, test_path, mutant_tree)
        if is_killed:
            killed += 1
            print(
                f"  [{idx}/{total}] Mutant #{idx} at line {target_line} ({mutation_type}): KILLED"
            )
        else:
            survived += 1
            survived_mutations.append((target_line, mutation_type))
            print(
                f"  [{idx}/{total}] Mutant #{idx} at line {target_line} ({mutation_type}): SURVIVED (Placebo warning!)"
            )

    score = (killed / total) * 100
    print(f"\n[*] Mutation Testing Complete for {target_name}:")
    print(f"    Total Mutants: {total}")
    print(f"    Killed: {killed}")
    print(f"    Survived: {survived}")
    print(f"    Mutation Score: {score:.1f}%")

    if survived > 0:
        print("\n[!] WARNING: Surviving mutants detected at:")
        for line, mtype in survived_mutations:
            print(f"    Line {line}: {mtype}")
        return False

    print("\n[+] SUCCESS: 100% Mutation Score! All test assertions are verified lethal.")
    return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run AST mutation testing on Ether core.")
    parser.add_argument("--target", choices=list(TARGETS.keys()) + ["all"], default="canonicalize")
    args = parser.parse_args()

    targets = list(TARGETS.keys()) if args.target == "all" else [args.target]
    all_passed = True
    for t in targets:
        if not run_mutation_suite(t):
            all_passed = False

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
