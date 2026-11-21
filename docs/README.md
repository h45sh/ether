# Ether Documentation Hub

Welcome to the **Ether** documentation index.

Ether is an open-source, reactive process supervisor, AST validator, and deterministic graph telemetry engine for cybersecurity tools and autonomous agents.

## Structure
- [Architecture](architecture/overview.md): High-level system design, deep modules, and unidirectional layer DAG.
- [Standards](standards/engineering.md): Concrete coding standards, AST verification, and testing tiers.
- [Adapters](developer/adapters.md): Specification and guide for writing pluggable security tool adapters.
- [Glossary](standards/glossary.md): Authoritative domain vocabulary and ubiquitous language.
- [Roadmap](../ROADMAP.md): High-level release milestones and strategic development plan.
EOF && \
cat << 'EOF' > /home/harsh/Documents/ether/docs/standards/glossary.md
# Domain Vocabulary & Ubiquitous Language

To prevent architectural degradation and semantic drift, all code, documentation, and agent reasoning in Ether must adhere to these exact definitions:

- **Workspace:** Top-level container grouping related sessions for an engagement or client scope. (*Avoid:* Project, folder, group).
- **Session:** Persistent investigation timeline stored in SQLite containing graph nodes and immutable event logs. (*Avoid:* Tab, run, instance).
- **ExecutionSession:** Runtime supervisor managing active process lifecycles, output streams, and memory ring buffers. (*Avoid:* Job runner, terminal instance).
- **ActionGateway:** Security module governing execution policies, SSRF defenses, CIDR scope limits, and variable resolution. (*Avoid:* Validator, firewall).
- **Finding:** Canonicalized, structured unit of security intelligence inheriting `BaseFinding`. (*Avoid:* Result, discovery, raw line).
- **Action:** Explicit recorded invocation of a security tool or shell command. (*Avoid:* Job, task, subprocess).
- **Adapter:** Pluggable Python module implementing `ToolAdapter` that encapsulates CLI command building and streaming output parsing. (*Avoid:* Driver, wrapper, script).
- **Primary Identity Key (PIK):** Deterministic set of attributes defining unique entity identity (used to compute the SHA-256 node ID).
EOF && \
cat << 'EOF' > /home/harsh/Documents/ether/docs/architecture/overview.md
# Ether Architecture Overview

Ether is built on the philosophy of **Deep Modules** (John Ousterhout) and a **Pure Core / Imperative Shell** unidirectional layer DAG.

## Unidirectional Layer DAG

```
┌────────────────────────────────────────────────────────┐
│  Headless Interfaces: CLI, Python SDK, MCP Server       │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  ActionGateway (Policy, SSRF Guard, Radix Trie Scope)  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  ExecutionSession (Process Supervisor, Ring Buffers)   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  GraphStore (SQLite WAL, SHA-256 PIK, Event Sourcing)  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  ToolRegistry & Pluggable Smart Adapters (tools/*)     │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Normalized Schemas (BaseFinding) & Core Primitives    │
└────────────────────────────────────────────────────────┘
```

## Core Deep Modules
1. **`ExecutionSession` (`ether.core.session`):**
   - Small Interface: `run_action()`, `get_stream()`, `stop_action()`.
   - Big Implementation: Async pipe draining, 64KB disk spooling, capped ring buffers, process exit monitoring.
2. **`GraphStore` (`ether.graph.store`):**
   - Small Interface: `upsert_finding()`, `get_node()`, `query_nodes()`.
   - Big Implementation: Deterministic PIK hashing, non-destructive graph attribute merging, SQLite WAL pooling, parent-child relationship auto-wiring.
3. **`ActionGateway` (`ether.gateway.gate`):**
   - Small Interface: `validate_action()`, `resolve_variables()`.
   - Big Implementation: Longest-prefix IP Radix Trie matching, cloud metadata SSRF defense, variable template interpolation, and `GatePolicy` enforcement.
