# Ether Concrete Engineering & Code Quality Standards

These standards are mechanically enforced via automated linting and AST verification.

## 1. Zero UI Code Invariant
- **Rule:** Under no circumstances may any file inside `src/ether/` import `textual`, `curses`, or any TUI/GUI presentation library.
- **Enforcement:** Enforced via AST inspection in `tests/unit/test_architecture.py`.

## 2. Process Execution Standards
- **Rule:** Never use `shell=True`, `os.system()`, or string concatenation to build commands.
- **Rule:** Never spawn child processes without passing through `sanitize_subprocess_env()` to strip system secrets.
- **Rule:** Every tool execution must use argument vectors (`List[str]`).

## 3. Database & State Standards
- **Rule:** 100% of SQLite database queries must use parameterized placeholders (`?`). String formatting or interpolation into SQL is strictly forbidden.
- **Rule:** Never open and close connections per query. Use the shared connection pool via `GraphStore._get_conn()`.
- **Rule:** All SQLite connections must enforce:
  ```sql
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  ```

## 4. Adapter Authoring Standards
- Adapters in `tools/<name>/` must implement `ToolAdapter`.
- Adapters must be stateless and thread-safe.
- Line parsers must yield subclasses of `BaseFinding`.
- Every adapter must pass the universal 4-stream fuzzing suite (`Broken ANSI`, `Truncated JSON`, `Null Bytes`, `20k-Token Buffer`).

## 5. Code Quality Gates
- **Linter:** `ruff check .` (zero warnings or errors).
- **Formatter:** `ruff format .` (line length: 100).
- **Target Python Version:** `>= 3.11` (specifically tested on `py311`, `py312`, `py313`).
- **Pre-commit Checks:**
  1. `ruff check .`
  2. `pytest -m tier0` (Invariants and property tests in <2 seconds).
  3. `pytest -m fast` (Fast unit tests in <5 seconds).
EOF && \
cat << 'EOF' > /home/harsh/Documents/ether/docs/developer/adapters.md
# Authoring Pluggable Security Tool Adapters

Ether's architecture follows the **Smart Adapter / Simple Core** principle. The core engine knows nothing about specific security tools. Every tool is a self-contained plugin inside `tools/<tool_name>/`.

## Plugin Structure

```
tools/<tool_name>/
├── manifest.toml    # Metadata, category, binary name, inputs & outputs
└── adapter.py       # Python class inheriting from ToolAdapter
```

## 1. `manifest.toml` Specification

```toml
[meta]
name = "nmap"
description = "Network exploration tool and security / port scanner"
category = "Network"
categories = ["Network", "PortScan"]
binary = "nmap"

[modes]
power = true

[input]
accepts = ["network.host"]

[output]
produces = ["network.host", "network.service"]
```

## 2. `adapter.py` Specification

```python
from typing import AsyncIterator, Dict, Any, List
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkService


class NmapAdapter(ToolAdapter):
    def validate_install(self) -> bool:
        """Check if binary exists in PATH."""
        import shutil

        return shutil.which("nmap") is not None

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Construct safe argument vector."""
        ip = target.data.get("ip") or "127.0.0.1"
        return ["nmap", "-sV", ip]

    async def parse_output(
        self, line: str, target: BaseFinding, context: Dict[str, Any]
    ) -> AsyncIterator[BaseFinding]:
        """Streamingly parse single stdout lines into normalized findings."""
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_proto = parts[0].split("/")
            yield NetworkService.create(
                host_ip=target.data.get("ip"),
                port=int(port_proto[0]),
                protocol=port_proto[1],
                service=parts[2],
            )
```

## 3. Automated Verification
All adapters are automatically validated against the universal fuzzing test:
```bash
pytest tests/unit/test_parsers/test_fuzz_all_adapters.py
```
