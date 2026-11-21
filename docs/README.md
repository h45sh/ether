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
  - [Quickstart Tutorial]            │      - [Authoring Tool Adapters]
    (tutorials/quickstart.md)        │        (how-to/author-adapters.md)
                                     │      - [Headless CLI Operations]
                                     │        (how-to/cli-usage.md)
                                     │      - [Contributing Guidelines]
                                     │        (how-to/contributing.md)
 ────────────────────────────────────┼────────────────────────────────────
                                     │
             Explanation             │               Reference
     (Understanding-Oriented)        │         (Information-Oriented)
   "Help me understand how it works" │     "Give me the technical specs"
   - [Architecture Deep Dive]        │     - [Schema Registry]
     (explanation/architecture.md)   │       (reference/schema-registry.md)
   - [Database & Graph State]        │     - [Domain Glossary]
     (explanation/database.md)       │       (reference/glossary.md)
                                     │     - [Engineering Standards]
                                     │       (reference/engineering-standards.md)
                                     ▼
                                THEORETICAL
```

---

## Direct Links

### 1. Tutorials
* **[Quickstart Tutorial](tutorials/quickstart.md)**: Initialize SQLite WAL storage, discover adapters, and upsert findings in 5 minutes.

### 2. How-To Guides
* **[Authoring Pluggable Tool Adapters](how-to/author-adapters.md)**: Add new security tools to Ether using `ToolAdapter` and `manifest.toml`.
* **[Headless CLI Operations](how-to/cli-usage.md)**: Running scans, inspecting sessions, and exporting investigations.
* **[Contributing Guidelines](how-to/contributing.md)**: Coding standards, mechanical quality gates, and pull request checklist.

### 3. Reference
* **[Schema Registry](reference/schema-registry.md)**: Official catalog of all 18 normalized finding models (`BaseFinding`, `network.host`, `network.service`, `vulnerability.found`).
* **[Engineering Standards](reference/engineering-standards.md)**: AST mechanical gates, zero UI imports, memory caps, and testing invariants.
* **[Domain Glossary](reference/glossary.md)**: Authoritative ubiquitous language and terminology.

### 4. Explanation
* **[Architecture Overview](explanation/architecture.md)**: Deep module philosophy, pure core vs. imperative shell, and layer DAG.
* **[Database & Graph Telemetry](explanation/database.md)**: SQLite WAL mode, Primary Identity Key (PIK) hashing, graph node merging, and event sourcing.
* **[Master Roadmap](../ROADMAP.md)**: The 5 Evolutionary Epochs to the ultimate ideal state of the engine.
