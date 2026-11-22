# Ether Architecture & Domain Glossary

This document defines the authoritative ubiquitous language, domain concepts, and architectural patterns used across the Ether codebase and documentation. The canonical root definition lives in [GLOSSARY.md](../../GLOSSARY.md).

---

## Core Domain Concepts

**Finding**:
A normalized, structured domain entity (host, service, vulnerability, credential) discovered by a security tool during execution.
_Avoid_: Scan result, raw output, log entry, match

**Primary Identity Key (PIK)**:
A deterministic composite identity key derived from an entity's immutable semantic attributes, enabling idempotent upserts and non-destructive graph merges.
_Avoid_: Entity ID, primary key, hash key, GUID

**Entity Graph**:
A persistent directed graph representing the discovered attack surface, where nodes represent findings and edges represent structural relationships.
_Avoid_: Target database, topology map, inventory list

**Smart Adapter / Simple Core**:
An architectural pattern where tool-specific binary discovery, argument assembly, and stream parsing live entirely in pluggable adapters, keeping the execution engine tool-agnostic.
_Avoid_: Dumb framework, wrapper script, plugin system

---

## Execution & Policy Engine

**Execution Session**:
An isolated, headless asynchronous runtime context supervising child process lifecycles, streaming raw logs, and emitting validated findings.
_Avoid_: Terminal session, workspace run, shell job, task

**Action Gateway**:
The authoritative perimeter security boundary that validates targets, enforces CIDR scope containment, and blocks metadata/SSRF destinations prior to process launch.
_Avoid_: Firewall, router, proxy, permission checker

**Gate Policy**:
The operational security mode (`SAFE` vs `UNRESTRICTED`) dictating destination filtering, scope enforcement, and command execution boundaries.
_Avoid_: Security level, access mode, permission tier

**Action Validator**:
A decoupled verification interface that validates intended tool invocations against operational policies before execution begins.
_Avoid_: Pre-flight hook, check runner, sanitizer

**Tool Adapter**:
A self-contained module encapsulating CLI argument formulation, binary discovery, and stream parsing into normalized finding schemas.
_Avoid_: Tool wrapper, parser plugin, driver

---

## Security & Forensics

**Untrusted Scan Output**:
Raw, unverified data emitted by child tools, encapsulated in structural XML boundaries to isolate language models from prompt injection.
_Avoid_: Unsafe output, raw terminal log, dirty string

**Subprocess Environment Scrubbing**:
The mechanical stripping of host secrets, API tokens, and provider credentials from the environment before spawning child processes.
_Avoid_: Env sanitization, secret masking, variable clearing

**Forensic Sealing**:
The permanent transition of a closed session into an immutable state that forbids all further mutation to preserve evidentiary integrity.
_Avoid_: Archive locking, session freeze, close session

**Event Log**:
An append-only, chronologically ordered sequence of every action executed and finding recorded within a session.
_Avoid_: Audit trail, transaction log, history table

---

## Agent Telemetry & Protocol (Epoch 2)

**Action-Scoped Diff**:
The set-theoretic delta ($\Delta_{action} = S_{action\_end} \setminus S_{action\_start}$) representing nodes and edges created or updated specifically by a distinct execution `action_id`, eliminating clock drift and concurrency races.
_Avoid_: Timestamp delta, poll diff, interval scan

**Agent Telemetry Protocol**:
The structured communication layer (over MCP) that presents token-budgeted graph snapshots, zero-token deltas, and supervised tool execution to autonomous AI agents.
_Avoid_: Agent API, bot bridge, AI driver

**Session Binding**:
The runtime attachment of an MCP server or client context to a persistent session, isolating graph findings and telemetry across parallel agent investigations.
_Avoid_: Context pin, workspace lock, active session flag

**Delta Envelope**:
The canonical structured JSON response containing categorized `added_nodes`, `updated_nodes`, and `added_edges` resulting from an action or state interval.
_Avoid_: Diff blob, patch payload, change list

**Sync-with-Fallback Execution**:
An execution pattern where tool invocations are awaited synchronously up to a configured deadline, automatically falling back to detached background supervision if the operation exceeds the threshold.
_Avoid_: Hybrid polling, timeout detach, deferred execution

---

## Temporal Graph Decay & Identity Invariance (Epoch 2)

**Confidence Decay Window**:
A bounded time interval (`ttl_seconds`) during which an entity finding remains in a `confirmed` status before transitioning to `flapping` or `stale`.
_Avoid_: Cache TTL, record expiration, delete timeout

**Invariant Identity Anchoring**:
The architectural mechanism that decouples logical entity identity from volatile IP addresses by binding Primary Identity Keys to persistent cryptographic fingerprints.
_Avoid_: Fixed IP mapping, static binding, hardware lock

**Cross-IP Migration**:
The deterministic graph reconciliation process where an entity observed at a new IP address inherits the historical lineage and edges of its previous instance.
_Avoid_: IP update, node overwrite, alias merge

**Flapping Node**:
An entity whose observation status or bound network address oscillates rapidly across successive actions within its active time-to-live window.
_Avoid_: Bouncing host, unstable port, dynamic target

**Anchor Hash**:
A standardized, deterministic `<type>:<hash>` fingerprint indexing an entity to its persistent cryptographic or behavioral identity.
_Avoid_: Fingerprint key, identity token, cert hash

---

## Vector Memory & Finding RAG (Epoch 2)

**vec0 Virtual Table**:
A native SQLite virtual table engine provided by `sqlite-vec` enabling in-process cosine, L2, and dot-product vector search directly over 384-dimensional finding embeddings.
_Avoid_: Vector database, vector index file, embedding cache

**Vector Embedding Engine**:
A deterministic, pure-offline component that maps finding text strings to 384-dimensional unit vector float arrays without remote network egress.
_Avoid_: Remote embedder, OpenAI wrapper, cloud vectorizer

**Semantic Text Template**:
A declarative, human-readable stringification method on `BaseFinding` (`to_semantic_text()`) that structures finding attributes into clean natural language sentences for optimal vector retrieval.
_Avoid_: Raw JSON dump, stringified dict, toString

**Finding RAG**:
The retrieval-augmented generation pattern in `GraphTelemetryCompiler` and MCP tools that pulls semantically related vulnerabilities, services, and credentials based on an agent's tactical objective.
_Avoid_: Document search, semantic lookup, finding search

