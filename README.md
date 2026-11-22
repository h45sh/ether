<div align="center">

# ETHER

**The Reactive Telemetry & Process Supervisor Substrate for Cybersecurity Tooling & Autonomous AI Agents**

[![CI](https://github.com/h45sh/ether/actions/workflows/ci.yml/badge.svg)](https://github.com/h45sh/ether/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Architecture: Headless Core](https://img.shields.io/badge/architecture-headless%20core-success)](docs/explanation/architecture.md)

*Ether operates as a deterministic "Operating System Kernel" for security operations—supervising CLI processes, normalizing streaming stdout/stderr, and maintaining a live, event-sourced entity graph without UI bloat.*

</div>

---

## Why Ether?

Security tools like `nmap`, `nuclei`, `ffuf`, and `gobuster` are essential, but orchestrating them in modern workflows or autonomous AI agent loops is notoriously painful:
- **Unstructured Noise:** Tools spew thousands of lines of terminal ANSI garbage. Parsing stdout line-by-line in ad-hoc bash scripts is brittle.
- **Context Window Exhaustion:** AI LLM agents running raw bash subshells burn through tens of thousands of tokens per scan, lose state across commands, and suffer from hallucinations.
- **No Unified World State:** Discovered entities (hosts, ports, URLs, CVEs) are trapped in disparate text files or terminals without a shared relational model.

**Ether solves this at the substrate level.**

```
┌────────────────────────────────────────────────────────────────────────┐
│                   APPLICATIONS & AGENTS (Userland)                     │
│                                                                        │
│  [Autonomous AI Agents]        [Power Workstations]     [CyGuide Labs] │
│    (Cursor, Claude, MCP)          (Red-Team Beast)         (Education) │
└────────────┬────────────────────────────┬───────────────────────┬──────┘
             │                            │                       │
             ▼                            ▼                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        ETHER UNIFIED RUNTIME API                       │
├────────────────────────────────────────────────────────────────────────┤
│                           ETHER CORE ENGINE                            │
│                                                                        │
│  ┌──────────────────┐  ┌─────────────────────┐  ┌───────────────────┐  │
│  │ Process & Ring   │  │ Reactive GraphStore │  │ GatePolicy Seam   │  │
│  │ - 64KB Spooler   │  │ - SHA-256 PIK Nodes │  │ - SAFE (SSRF/IMDS)│  │
│  │ - Bounded RAM    │  │ - Idempotent Upsert │  │ - UNRESTRICTED    │  │
│  │ - Zero shell=True│  │ - Event Sourcing    │  │   (Beast Mode)    │  │
│  └──────────────────┘  └─────────────────────┘  └───────────────────┘  │
│                                │                                       │
│                                ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Pluggable Smart Adapters (nmap, nuclei, ffuf, subfinder, etc.)    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

* **Universal Smart Adapters:** Completely tool-agnostic plugin framework (`tools/<name>/`). Adapters encapsulate argument building and streaming output parsing into normalized Pydantic schemas.
* **Deterministic Reactive Graph:** Entities (Hosts, Services, Vulnerabilities, Endpoints) are identified by deterministic SHA-256 **Primary Identity Keys (PIK)** and merged non-destructively in SQLite WAL mode.
* **Autonomous Agent Optimization (Zero-Token Diffs):** Instead of flooding an LLM with 50,000 tokens of raw console logs, Ether returns compact semantic graph deltas ($\Delta = S_{t+1} \setminus S_t$), cutting context consumption by **98%**.
* **Dual Security Policy Seam (`GatePolicy`):**
  - `GatePolicy.SAFE`: Blocks cloud metadata (AWS IMDS, GCP, Azure), enforces CIDR scope boundaries, and strips credentials.
  - `GatePolicy.UNRESTRICTED`: Unlocks raw, unconstrained execution for sovereign red-teams and offensive operations.
* **Process Supervisor & Memory Bounded:** Runs binaries via pure argument vectors (`asyncio.create_subprocess_exec`), spools raw streams to disk with 64KB buffering, and bounds in-memory ring buffers (`maxlen=5000`) keeping memory under **10 MB**.
* **Zero UI Invariant:** 100% headless. Zero dependencies on Textual, curses, or GUI libraries. Mechanically verified via AST linting.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/h45sh/ether.git
cd ether

# Install using uv (recommended)
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## Quick Start

```python
import asyncio
from ether import GraphStore, ToolRegistry, ActionGateway, GatePolicy
from ether.schemas.network import NetworkHost


async def main():
    # 1. Initialize SQLite WAL Storage (in-memory or on disk)
    store = GraphStore(":memory:")
    await store.initialize()

    # 2. Create Workspace and Investigation Session
    ws_id = await store.create_workspace("Engagement Delta")
    sess_id = await store.create_session(ws_id, "Recon Phase")

    # 3. Discover Tool Adapters (Nmap, Nuclei, FFUF, etc.)
    registry = ToolRegistry()
    registry.load_tools()

    # 4. Enforce Policy (SAFE for labs, UNRESTRICTED for red teams)
    gateway = ActionGateway(registry, store, policy=GatePolicy.SAFE)

    # 5. Record Discovered Finding
    host = NetworkHost.create(ip="10.10.10.5", hostname="target.htb")
    node_id = await store.upsert_finding(sess_id, host)

    # 6. Retrieve Normalized Entity Node
    node = await store.get_node(sess_id, node_id)
    print(f"Discovered: {node['schema_type']} -> {node['pik_json']}")

    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Testing & Verification

Ether adheres to the **"Review Proof, Not Code"** engineering model. Every release must satisfy 100% of local mechanical gates:

```bash
# Run Tier 0 AST Invariants & Property-Based Tests (<2s)
pytest -m tier0

# Run Universal Adapter Fuzzing Suite across all 11 tool adapters
pytest -m fuzz

# Run Full Regression Suite (166 tests)
pytest tests/

# Code Style & Quality Check
ruff check .
ruff format --check .
```

---

## Documentation Index

Our documentation follows the **[Diátaxis Framework](https://diataxis.fr/)**:

| Quadrant | Document | Description |
| :--- | :--- | :--- |
| **Tutorial** | [Quickstart Guide](docs/tutorials/quickstart.md) | First steps initializing graphs, loading adapters, and querying telemetry. |
| **How-To** | [Authoring Tool Adapters](docs/how-to/author-adapters.md) | Specification for writing streaming parsers in `tools/`. |
| **How-To** | [Headless CLI Operations](docs/how-to/cli-usage.md) | Running tool sessions and investigations headless from CLI. |
| **How-To** | [Contributing Standards](docs/how-to/contributing.md) | Pull request guidelines, AST checks, and code hygiene. |
| **Reference** | [Schema Registry](docs/reference/schema-registry.md) | Complete catalog of 18 normalized `BaseFinding` schemas. |
| **Reference** | [Engineering Standards](docs/reference/engineering-standards.md) | Concrete mechanical invariants, memory limits, and policies. |
| **Reference** | [Domain Glossary](GLOSSARY.md) | Ubiquitous language: Finding, PIK, Entity Graph, Session, Gateway. |
| **Explanation** | [Architecture Overview](docs/explanation/architecture.md) | Deep module design, unidirectional layer DAG, and streaming backpressure. |
| **Explanation** | [Database & Graph State](docs/explanation/database.md) | SQLite WAL mode, PIK hashing, and append-only event sourcing. |
| **Vision** | [Master Roadmap](ROADMAP.md) | The 5 Evolutionary Epochs to the ideal autonomous security engine. |

---

## Master Roadmap Summary

- **Epoch 1:** Hardened Substrate & Decoupled Core *(Current - v0.1.0)*
- **Epoch 2:** Autonomous Agent Telemetry Protocol (MCP & Zero-Token Diffs) *(v0.3.0)*
- **Epoch 3:** High-Throughput Chained Execution & Pipeline DAG *(v0.4.0)*
- **Epoch 4:** The Unrestricted "Beast" Offensive Engine (PTY & Attack Paths) *(v0.5.0)*
- **Epoch 5:** Distributed Sovereign Mesh & Global Telemetry *(v1.0.0+)*

*See the full [ROADMAP.md](ROADMAP.md) for detailed deliverables.*

---

## License

Ether is open-source software licensed under the [MIT License](LICENSE).
