# Ether Documentation Hub

Welcome to the **Ether Documentation Hub**.

Ether is a headless, reactive process supervisor, AST validator, and deterministic graph telemetry engine for cybersecurity tooling and autonomous AI agents.

Our documentation strictly follows the **[Diátaxis Framework](https://diataxis.fr/)**, organizing knowledge across four distinct modes: **Tutorials** (learning-oriented), **How-To Guides** (problem-oriented), **Reference** (information-oriented), and **Explanation** (understanding-oriented).

---

## Find Documentation by Your Goal

Select your persona or operational goal to jump directly to the relevant guides:

### I am building or connecting an AI Agent (Claude, Cursor, Swarms)
* **Start here:** [Quickstart Tutorial](tutorials/quickstart.md) — Walk through an end-to-end session from scratch.
* **Integrate MCP:** [Agent Telemetry & MCP Integration Guide](how-to/agent-telemetry-mcp.md) — Connect Claude Desktop, Cursor, or agent swarms via native MCP tools.
* **Understand Zero-Token Diffs:** [Architecture Deep Dive](explanation/architecture.md) — Learn how set-theoretic deltas save 98% of context tokens.

### I am a Security Operator or Red-Teamer (CLI & Unrestricted Policy)
* **Master the CLI:** [Headless CLI Operations Manual](how-to/cli-usage.md) — Full reference for all 8 subcommands (`doctor`, `tool`, `run`, `session`, `graph`, `telemetry`, `logs`, `mcp`).
* **Unconstrained Execution:** Learn how to unlock raw, unconstrained execution using `--policy unrestricted` in [GatePolicy Reference](reference/engineering-standards.md).
* **Forensic Archiving:** Export and import encrypted session databases using AES-256-GCM in [CLI Operations Guide](how-to/cli-usage.md#7-exporting--importing-investigation-archives).

### I am a Python Developer or Tool Author (SDK & Adapters)
* **Start with DevKit:** [Ether DevKit](https://github.com/h45sh/ether-devkit) — Official developer CLI and agent skill for authoring, scaffolding, and validating adapters.
* **Programmatic Quickstart:** Embed Ether into Python apps via [Quickstart Tutorial](tutorials/quickstart.md#step-8-taking-it-programmatic-python-sdk).
* **Write Custom Adapters:** [Authoring Pluggable Tool Adapters](how-to/author-adapters.md) — Create Tier A in-process async coroutines or Tier B subprocess parsers.
* **Inspect Finding Schemas:** [Schema Registry Catalog](reference/schema-registry.md) — Specifications for all 18 normalized Pydantic finding models.

### I am a DevOps or Platform Engineer (Docker & CI/CD)
* **Container Workflows:** Run Ether via multi-arch container images in the [README Quickstart](../README.md#method-4-docker-container-for-containerized--cloud-workflows).
* **Automated CI Security Gates:** Integrate automated regression scanning with `ether run` into your CI pipelines.
* **Performance Benchmarks:** Inspect verified throughput, query latency, and memory ceilings in [Mechanical Performance Benchmarks](benchmarks/README.md).

---

## Diátaxis Documentation Navigation Matrix

```text
                                  PRACTICAL (Doing)
                                         ▲
                                         │
               Tutorials                 │             How-To Guides
          (Learning-Oriented)            │          (Problem-Oriented)
       "Show me how to get started"      │      "Show me how to solve a task"
       - [Quickstart Tutorial]           │      - [Headless CLI Operations]
         (tutorials/quickstart.md)       │        (how-to/cli-usage.md)
                                         │      - [Agent Telemetry & MCP]
                                         │        (how-to/agent-telemetry-mcp.md)
                                         │      - [Authoring Tool Adapters]
                                         │        (how-to/author-adapters.md)
                                         │      - [Contributing Guidelines]
                                         │        (CONTRIBUTING.md)
     ────────────────────────────────────┼────────────────────────────────────
                                         │
                 Explanation             │               Reference
          (Understanding-Oriented)       │         (Information-Oriented)
        "Help me understand the why"     │     "Give me the technical specs"
        - [Architecture Deep Dive]       │     - [Schema Registry (18 Models)]
          (explanation/architecture.md)  │        (reference/schema-registry.md)
        - [Database & Graph State]       │     - [Engineering Standards]
          (explanation/database.md)      │        (reference/engineering-standards.md)
        - [Performance Benchmarks]       │     - [Domain Glossary]
          (benchmarks/README.md)         │        (reference/glossary.md)
                                         │     - [Master Roadmap (5 Epochs)]
                                         │        (../ROADMAP.md)
                                         ▼
                                 THEORETICAL (Knowing)
```

---

## Direct Documentation Links

### 1. Tutorials (Learning)
* **[Quickstart Tutorial](tutorials/quickstart.md)**: A 10-minute hands-on lesson guiding you through diagnostics, session creation, supervised scanning, semantic vector search, AI telemetry deltas, and encrypted forensic export.

### 2. How-To Guides (Problem-Solving)
* **[Headless CLI Operations Manual](how-to/cli-usage.md)**: Authoritative operational manual for all 8 subcommands, global flags, and error handling.
* **[Agent Telemetry & MCP Integration](how-to/agent-telemetry-mcp.md)**: Step-by-step setup for Claude Desktop, Cursor, and custom agent swarms with zero-token diffs and finding RAG.
* **[Authoring Pluggable Tool Adapters](how-to/author-adapters.md)**: Complete guide to implementing Tier A in-process async coroutines and Tier B subprocess tool adapters with `manifest.toml`.
* **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, code standards, PR checklists, and mechanical quality gates.
* **[Security Policy](SECURITY.md)**: Vulnerability disclosure, bug bounty guidelines, and reporting channels.

### 3. Reference (Facts & Specifications)
* **[Schema Registry](reference/schema-registry.md)**: Authoritative specification of all 18 normalized finding schemas, Primary Identity Keys (PIK), and child relations.
* **[Engineering Standards](reference/engineering-standards.md)**: Strict headless invariants, deep module principles, memory limits, and testing standards.
* **[Domain Glossary](reference/glossary.md)**: Ubiquitous language defining core concepts like PIK, Zero-Token Diff, Flapping State, and GatePolicy.
* **[Performance Benchmarks](benchmarks/README.md)**: Quantitative speed, throughput, and memory measurements verified across CI and release preflights.

### 4. Explanation (Architecture & Design)
* **[Architecture Overview & Engine Model](explanation/architecture.md)**: The supervisory runtime substrate, 6 core subsystems, deep module philosophy, information hiding, unidirectional layer DAG, and reactive execution pipelines.
* **[Database & Graph State](explanation/database.md)**: SQLite WAL mode, Primary Identity Key hashing, idempotent upserts, temporal state decay, cryptographic identity anchoring, and offline vector indexing.
* **[Master Roadmap](../ROADMAP.md)**: The 5 Evolutionary Epochs from hardened substrate to the ultimate headless security engine.
