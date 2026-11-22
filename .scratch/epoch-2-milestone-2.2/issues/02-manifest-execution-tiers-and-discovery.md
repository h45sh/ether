# 02: Manifest Execution Tiers & Discovery (manifest.toml)

**What to build:**
Update the tool manifest schema and registry discovery to support execution tiers. In `src/ether/registry/manifest.py`, add `execution_tier: str = "subprocess"` to `ToolManifest`. In `src/ether/registry/registry.py`, update `ToolRegistry.load_tools()` so that when `execution_tier == "coroutine"`, the binary check (`shutil.which`) is bypassed and Python dependency availability is checked. Update `ether tool list` and `ether tool info` in `src/ether/cli/commands/tool.py` to display the execution tier ("Coroutine" vs "Subprocess").

**Blocked by:** 01: ExecutionContext and ToolAdapter Dual-Execution Protocol Base

**Status:** completed

- [x] Add `execution_tier: str = "subprocess"` to `ToolManifest` in `src/ether/registry/manifest.py`
- [x] Update `ToolRegistry.load_tools()` in `src/ether/registry/registry.py` to support coroutine discovery without binary path lookups
- [x] Update `src/ether/cli/commands/tool.py` to display execution tier in terminal and JSON outputs
- [x] Add unit tests in `tests/unit/test_engine_registry.py` and `tests/unit/test_cli.py`
