# Ether Documentation Hub

Welcome to the **Ether** documentation hub.

Ether is an open-source, reactive process supervisor, AST validator, and deterministic graph telemetry engine for cybersecurity tooling and autonomous AI security agents.

Following the **[Diátaxis Framework](https://diataxis.fr/)**, the documentation is structured across four distinct modes: **Tutorials** (getting started), **How-To Guides** (solving operational problems), **Reference** (APIs and schemas), and **Explanation** (architecture and invariants).

---

## Documentation Navigation

```text
                                  PRACTICAL
                                     ▲
                                     │
           Tutorials                 │             How-To Guides
     (Learning-Oriented)             │          (Problem-Oriented)
  "Show me how to get started"       │      "Show me how to solve a task"
  - Quickstart Execution             │      - Writing a Tool Adapter
  - Headless Session Lifecycle       │      - Driving Ether via Python SDK
                                     │      - Connecting AI Agents via MCP
 ────────────────────────────────────┼────────────────────────────────────
                                     │
             Explanation             │               Reference
     (Understanding-Oriented)        │         (Information-Oriented)
   "Help me understand how it works" │     "Give me the technical specs"
   - Kernel Architecture & DAG       │     - Normalized Schema Registry
   - Deterministic Graph (PIK)       │     - SQLite Database Schema
   - Process Supervisor & Rings      │     - CLI & Engine API Reference
                                     │
                                     ▼
                                THEORETICAL
```

---

## 📚 Table of Contents

### 1. Explanation (Architecture & Design)
Deep dives into the internal mechanics and engineering philosophy of the engine:
* **[Architecture Overview](developer/ARCHITECTURE.md)**: Deep modules, pure core vs. imperative shell, and the unidirectional layer DAG.
* **[Database & Graph Telemetry](developer/DATABASE.md)**: SQLite WAL mode, Primary Identity Key (PIK) hashing, graph node merging, and event sourcing.
* **[Engineering Standards](standards/engineering.md)**: AST mechanical gates, zero UI imports, memory caps, and testing pyramids.
* **[Domain Glossary](GLOSSARY.md)**: Authoritative ubiquitous language and domain vocabulary.

### 2. Reference (Technical Specifications)
Precise contracts, schemas, and schemas:
* **[Schema Registry](developer/SCHEMA_REGISTRY.md)**: Canonical catalogue of all 18 normalized `BaseFinding` schemas.
* **[Adapter Specification](developer/adapters.md)**: `ToolAdapter` interface and `manifest.toml` recipe contracts.

### 3. How-To Guides (Developer & Operator Workflows)
Step-by-step guides for extending and integrating Ether:
* **[Authoring Tool Adapters](developer/adapters.md)**: Creating streaming stdout/stderr parsers for CLI scanners.
* **[Autonomous Agent Integration (MCP)](developer/ARCHITECTURE.md#5-agent-integration--zero-token-diffing)**: Connecting LLM agents via Model Context Protocol and receiving token-zero graph diffs.
* **[Contributing Guidelines](user/CONTRIBUTING.md)**: Quality gates, pre-commit checks, and code review standards.

### 4. Vision & Planning
* **[Master Roadmap](../ROADMAP.md)**: The phased roadmap to the ultimate ideal state of the engine.
