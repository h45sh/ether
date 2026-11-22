# 05: CLI Subcommand Integration and AST Layer DAG Gate

**What to build:**
Integrate the MCP server into Ether's command-line interface and enforce layer integrity. Register `ether mcp` in `src/ether/cli/router.py` with `--transport {stdio,sse}`, `--port`, `--session`, and `--policy` options. Update `tests/unit/test_architecture.py` with an AST import check verifying that `ether.mcp` is located at the top of the layer DAG and is never imported by `gateway`, `core`, `graph`, `schemas`, or `common`. Run full regression test suite (`pytest`) verifying zero performance regressions or layer leaks.

**Blocked by:** 04: Supervised Tool Execution and Prompt Sandboxing

**Status:** completed

- [x] Create `src/ether/cli/commands/mcp.py` implementing `handle_mcp`
- [x] Register `ether mcp` in `src/ether/cli/router.py` with help and arguments
- [x] Add AST layer DAG check in `tests/unit/test_architecture.py` enforcing `ether.mcp` isolation
- [x] Add CLI invocation test in `tests/unit/test_cli.py`
- [x] Run full test suite (`.venv/bin/pytest`) and linting (`.venv/bin/ruff check .`)
