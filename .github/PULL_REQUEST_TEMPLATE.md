## Summary

<!-- Briefly describe the purpose of this PR and the architectural problem it addresses. -->

Fixes # <!-- Issue number if applicable -->

---

## Type of Change

- [ ] Bug fix (non-breaking fix for an existing issue)
- [ ] New feature (non-breaking enhancement to engine or telemetry protocol)
- [ ] New tool adapter (`tools/<tool_name>/`)
- [ ] Core substrate modification (`src/ether/core/`, `src/ether/graph/`, or `src/ether/schemas/`)
- [ ] Documentation update
- [ ] CI / Workflow / Packaging change

---

## Architectural Tier Check

- [ ] **Tier 1 (Frozen Core)**: Modifies `src/ether/schemas/base.py`, `src/ether/graph/store.py`, `src/ether/registry/registry.py`, `src/ether/common/canonicalize.py`, or `src/ether/paths.py`. Requires CODEOWNERS review from `@h45sh`.
- [ ] **Tier 2 (Review Required)**: Modifies `src/ether/gateway/gate.py`, `src/ether/core/executor.py`, `src/ether/core/session.py`, `src/ether/schemas/*.py`, or tool adapters in `tools/*/`.
- [ ] **Tier 3 (Free to Change)**: Documentation (`docs/`), tests (`tests/`), operational scripts (`scripts/`), or roadmap files.

---

## Strict Headless Invariant Check

- [ ] **Zero UI Code**: This PR contains zero Textual imports, zero terminal widgets, and zero presentation code.
- [ ] **AST Verification**: Code passes Tier 0 AST mechanical linting (`pytest -m tier0`).
- [ ] **Process Isolation**: For tool adapters, external CLI commands are executed strictly as argument vectors (`List[str]`) without `shell=True`.

---

## Pre-Merge Verification Checklist

- [ ] Code formatted and linted cleanly: `ruff check .` and `ruff format --check .`.
- [ ] Fast pre-flight invariants pass: `pytest -m tier0` (<2s).
- [ ] Full regression suite executed and 100% passing: `bash scripts/verify.sh` (or `pytest tests/`).
- [ ] If finding schemas in `src/ether/schemas/` were added or modified, schema documentation has been regenerated: `python3 scripts/generate_schema_registry.py --check`.
- [ ] No decorative emojis in commit messages, documentation, or code.
- [ ] Environment sanitization preserved: Subprocess environments pass through `sanitize_subprocess_env()`.
