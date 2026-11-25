# Contributing to Ether: Developer & Adapter Guide

Thank you for your interest in contributing to Ether! This guide covers our architectural model, the plugin specification for adding new security tool adapters, our headless testing workflow, and code governance policies.

---

## 1. Architectural Philosophy: Smart Adapter / Simple Core

Ether strictly decouples process execution and graph telemetry from cybersecurity tooling:

* **The Core Framework (`src/ether/core`, `src/ether/graph`)**: Manages the asynchronous subprocess lifecycle, deterministic SQLite entity graph, vector embeddings, event logs, and the Agent Telemetry Protocol. It contains zero tool-specific logic.
* **The Tool Adapters (`tools/<tool_name>/`)**: Self-contained plugins that translate between external CLI commands (`nmap`, `gobuster`, `nuclei`, etc.) and Ether's unified finding schemas.

> [!IMPORTANT]
> **Strict Headless Invariant**: Under no circumstances may any file inside `src/ether/` import `textual`, `curses`, or any TUI/GUI presentation library. Ether is strictly an engine/substrate.

---

## 2. Anatomy of a Tool Plugin

> [!TIP]
> **Use Ether DevKit for Scaffolding & Linting**: We strongly recommend using **[Ether DevKit (`ether-devkit`)](https://github.com/h45sh/ether-devkit)** to scaffold new tool plugins (`ether-devkit new <tool>`) and validate existing ones (`ether-devkit validate tools/<tool>`) against our architectural invariants before submitting a PR.
>
> Install globally with `pipx install git+https://github.com/h45sh/ether-devkit.git` or load the skill into your coding agent via `npx skills add h45sh/ether-devkit -g -y`.

Every security tool plugin lives in its own subdirectory under `tools/<tool_name>/` and requires two files:

```text
tools/<tool_name>/
├── __init__.py
├── manifest.toml     # Metadata, execution constraints, input/output schemas
└── adapter.py        # Command generation and streaming output parsing logic
```

### A. The Declarative Manifest (`manifest.toml`)

The manifest informs Ether's registry about tool capabilities, inputs, and outputs:

```toml
[meta]
name = "mytool"
description = "Fast web directory and virtual host scanner"
one_line_summary = "Enumerate endpoints and paths on web targets"
category = "Web Reconnaissance"
categories = ["web", "enumeration"]
binary = "mytool"

[modes]
power = true

[input]
accepts = ["network.service", "web.endpoint"]

[output]
produces = ["web.endpoint", "web.vulnerability"]
```

### B. The Tool Adapter (`adapter.py`)

Adapters inherit from `ToolAdapter` in `ether.registry.adapter` and implement three core methods:

```python
import shlex
import shutil
from typing import Any, AsyncIterator, Dict, List, Optional
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebEndpoint


class MyToolAdapter(ToolAdapter):
    def validate_install(self) -> bool:
        """Check if the external CLI binary is available on PATH."""
        return shutil.which("mytool") is not None

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Construct the CLI arguments safely as an argument list (preventing shell injection)."""
        raw_flags = params.get("raw_flags", "")
        flag_args = shlex.split(raw_flags) if raw_flags else []
        url = target.data.get("url") or "http://127.0.0.1"
        return ["mytool", "-u", url] + flag_args

    async def parse_output(
        self, line: str, target: BaseFinding, context: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[BaseFinding]:
        """Parse raw stdout line-by-line into validated BaseFinding schemas."""
        cleaned = line.strip()
        if "200 OK" in cleaned:
            path = cleaned.split()[0]
            yield WebEndpoint.create(
                url=path,
                status_code=200,
            )
```

---

## 3. Standard Finding Schemas & Primary Identity Keys (PIKs)

To enable tool chaining, all findings inherit from `BaseFinding` and declare a deterministic **Primary Identity Key (PIK)**.

| Schema Type | Finding Class | PIK Identifying Fields |
| :--- | :--- | :--- |
| `network.host` | `NetworkHost` | `{"ip": "<ip_address>"}` |
| `network.service` | `NetworkService` | `{"host_ip": "<ip>", "port": <port>, "protocol": "<proto>"}` |
| `web.endpoint` | `WebEndpoint` | `{"url": "<url>"}` |
| `web.technology` | `WebTechnology` | `{"url": "<url>", "technology_name": "<name>"}` |
| `dns.record` | `DnsRecord` | `{"domain": "<domain>", "type": "<type>", "value": "<val>"}` |
| `vulnerability.found` | `VulnerabilityFound` | `{"host_ip": "<ip>", "vuln_id": "<cve_or_id>"}` |

> [!TIP]
> Consult [`reference/schema-registry.md`](reference/schema-registry.md) for the complete reference of all 25 active finding schemas.

---

## 4. Headless-First Development Workflow

Verify the **Executor → Adapter → GraphStore** pipeline in headless isolation using an in-memory SQLite database:

```python
import asyncio
from ether.graph.store import GraphStore
from ether.core.executor import Executor
from ether.schemas.web import WebEndpoint
from tools.mytool.adapter import MyToolAdapter


async def test_run():
    store = GraphStore(":memory:")
    await store.initialize()

    adapter = MyToolAdapter()
    executor = Executor(store)

    target = WebEndpoint.create(url="http://127.0.0.1:8000")
    cmd = adapter.build_command(target, {})
    print(f"Executing: {' '.join(cmd)}")

    await store.close()


if __name__ == "__main__":
    asyncio.run(test_run())
```

---

## 5. Code Governance & Tiered Protection Policy

To protect system determinism and database stability, Ether follows a three-tiered change governance model:

### Tier 1: Frozen Core (Strict Review Required)
> [!IMPORTANT]
> Foundational engine infrastructure. Zero breaking contract changes without architectural review.
* `src/ether/schemas/base.py`: The `BaseFinding` and `Relation` models.
* `src/ether/graph/store.py`: Upsert logic, PIK SHA-256 calculation, and database schemas.
* `src/ether/graph/write_queue.py`: Async write serialization queue and batch commit worker.
* `src/ether/graph/vector_index.py`: Offline `sqlite-vec` vector indexing and search engine.
* `src/ether/common/canonicalize.py`: Value and schema normalization rules.
* `src/ether/common/forensic_log.py`: Cryptographic hash-chained audit logging and compaction.
* `src/ether/registry/registry.py`: Dynamic tool discovery and manifest loader.
* `src/ether/paths.py`: Centralized application data path resolution.

### Tier 2: Review Required
* `src/ether/core/executor.py`: Subprocess streams, timeouts, and process group management.
* `src/ether/core/session.py`: ExecutionSession lifecycle and ring buffering.
* `src/ether/gateway/gate.py`: Action validation and policy enforcement.
* `src/ether/gateway/scope.py`: RadixTrie CIDR scope validation and IMDS defense.
* `src/ether/gateway/preflight.py`: Dynamic capability-driven preflight verification.
* `src/ether/schemas/*.py`: Domain finding schemas.
* `tools/*/adapter.py`: Individual tool adapters.

### Tier 3: Free to Change
* `docs/`: User and developer documentation.
* `scripts/`: Development and maintenance helper scripts.
* `tests/`: Automated unit, integration, and fuzz test suites.
* `ROADMAP.md`: Project evolution roadmap.

---

## 6. Running Verification & Continuous Integration

Before submitting a Pull Request, run the automated verification pipeline:

```bash
# 1. Code style and quality check
ruff check .
ruff format --check .

# 2. Run Tier 0 AST and mathematical property invariants (<3s)
pytest -m tier0

# 3. Run fast in-memory unit tests (<5s)
pytest -m fast

# 4. Run universal adapter fuzzing suite (ANSI, 20k tokens, truncated JSON, null bytes)
pytest -m fuzz

# 5. Run full test suite
pytest tests/
```

### Empirical Testing Standards

1. **Tier 0 AST Architectural Checks** (`tests/unit/test_architecture.py`):
   Mechanical AST enforcement banning dangerous patterns (`shell=True`, Textual/UI imports, direct `subprocess` imports in adapters, raw string SQL execution).
2. **Mathematical Properties with Hypothesis** (`tests/unit/test_properties.py`):
   Algebraic invariants: PIK hash order independence, canonicalization idempotence, SSRF metadata permutations, and GraphStore merge commutativity & idempotence.
3. **Universal Adapter Fuzzing** (`tests/unit/test_parsers/test_fuzz_all_adapters.py`):
   Every tool adapter is automatically registered and tested against 4 adversarial output streams (ANSI explosions, truncated JSON, 20,000-token strings, null bytes) and installation validation.
