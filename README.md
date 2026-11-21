# Ether

**Ether** is a reactive process supervisor, AST validator, and deterministic graph telemetry engine for cybersecurity tooling and autonomous AI agents.

## Core Capabilities
- **Universal Smart Adapters:** Process discovery, binary execution, and streaming output normalization.
- **Deterministic Reactive Graph:** Entities (Hosts, Services, Vulnerabilities, Endpoints) indexed and idempotently merged via SHA-256 Primary Identity Keys (PIK).
- **Process Supervisor:** High-throughput streaming with 64KB log spooling, ring buffering, and zero shell injection (`asyncio.create_subprocess_exec`).
- **Policy Engine:** SSRF / Cloud metadata defense, CIDR scope enforcement, and pluggable policies (Safe vs. Unrestricted).
- **Event Sourcing:** Complete immutable forensic replay log in SQLite WAL mode.

## Installation
```bash
pip install ether
```

## Basic Usage
```python
import asyncio
from ether.graph.store import GraphStore
from ether.core.session import ExecutionSession

async def main():
    store = GraphStore(":memory:")
    await store.initialize()
    # Execute tools, stream findings, query graph
    await store.close()

if __name__ == "__main__":
    asyncio.run(main())
```

## License
MIT
