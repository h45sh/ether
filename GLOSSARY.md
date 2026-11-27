# Ether Domain Model

Headless, reactive process supervision, AST validation, and deterministic graph telemetry engine for cybersecurity tooling and autonomous AI agents.

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

## Execution & Policy Engine

**Tool Arsenal**:
The collection of registered security tool adapters discoverable and executable by Ether, categorised by execution tier (`coroutine` vs `subprocess`).
_Avoid_: Plugin list, tool directory, script folder

**Graph Analytics**:
Deterministic graph algorithms (BFS attack paths, transitive blast radius, crown-jewel identification, betweenness centrality) executed over the entity graph.
_Avoid_: Heuristics, AI reasoning, network scanning

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

## Dual-Execution Engine (Epoch 2)

**Dual-Execution Protocol**:
A unified execution model allowing tool adapters to execute either as high-throughput native async coroutines or isolated OS subprocesses behind an identical generator seam.
_Avoid_: Hybrid runtime, mixed runner, polyglot executor

**Tier A Adapter (Native Async Coroutine)**:
A zero-fork, memory-bounded tool adapter implemented directly within the asyncio event loop for ultra-high-throughput operations.
_Avoid_: In-memory tool, Python plugin, light runner

**Tier B Adapter (Binary Subprocess)**:
A supervised process adapter executing compiled binaries via isolated OS subprocesses with output streaming, disk spooling, and secret scrubbing.
_Avoid_: External tool, heavy runner, OS binary

**Execution Context**:
The contextual execution environment passed to adapters providing action attribution, disk logging sinks, secret scrubbing, and process runner hooks.
_Avoid_: Run context, env bag, worker state

## Temporal Graph & Cryptographic Identity

**Temporal State Decay**:
The deterministic confidence degradation of graph entities over time (`proposed` → `confirmed` → `flapping` → `stale`) based on observation timestamps and time-to-live thresholds.
_Avoid_: Aging out, cache expiration, eviction, stale data

**Invariant Identity Anchoring**:
The technique of coupling volatile network findings (IP/port) to persistent cryptographic or structural fingerprints (TLS certificates, SSH host keys, HTTP favicons) to track entity migration without creating duplicate orphan nodes.
_Avoid_: Host tracking, IP mapping, alias table, entity merging

**Flapping Node**:
An entity whose observation status or bound network address oscillates rapidly across successive actions within its active time-to-live window.
_Avoid_: Bouncing host, unstable port, dynamic target

**Anchor Hash**:
A standardized, deterministic `<type>:<hash>` fingerprint indexing an entity to its persistent cryptographic or behavioral identity.
_Avoid_: Fingerprint key, identity token, cert hash

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

## Substrate Optimizations & Drift Analytics (Epoch 3)

**Architectural Drift**:
The measured structural divergence between an observed entity graph and a verified baseline specification, expressed as discrepancy findings across network surfaces, services, and endpoints.
_Avoid_: Configuration audit, state diff, compliance scan, environment skew

**Baseline Calibration**:
A synthetic preflight probe dispatched by a web discovery tool to ascertain ambient 404 response geometry, deriving negative filter bounds to prevent graph pollution.
_Avoid_: Fuzz tuning, 404 test, warmup scan, response profiling

**Async Write Queue**:
An asynchronous serialization channel that orders concurrent graph mutation requests through a single dedicated write connection to prevent contention in append-heavy workloads.
_Avoid_: Task pool, write lock, transaction worker, batch worker

**Drift Discrepancy Finding**:
A normalized domain finding (`audit.drift`) denoting a specific topological divergence (such as an unexpected open port, absent expected service, or missing required HTTP header) between an observed session graph and an architectural baseline specification.
_Avoid_: Diff node, discrepancy record, drift error, violation finding

**Audit Manifest & Cryptographic Hash Chain**:
An append-only, tamper-evident JSONL ledger (`AuditRecord`) linking each supervised action's payload, raw output log hash, and preceding block hash via SHA-256 for mathematical verification of the chain of custody.
_Avoid_: Action history, command log, tracking file, audit dump

**Scope Validator**:
A high-leverage RadixTrie-backed network boundary engine in `ActionGateway` that enforces strict CIDR containment and permanently neutralizes cloud metadata/IMDS destinations under `GatePolicy.SAFE`.
_Avoid_: Network filter, IP checker, range checker

**Engagement Scope**:
The declarative Rules of Engagement boundary (`allowed_cidrs`, `allowed_domains`, and explicit opt-ins for loopback, link-local, or metadata targets) evaluated by `Scope Validator` before tool dispatch or network connection.
_Avoid_: Target whitelist, scope config, IP allowlist

**Reactive Pipeline**:
A multi-stage, backpressure-bounded execution chain (`PipelineEngine`) that streams `Finding` entities from upstream `Tool Adapter` stages into downstream stages with single-owner persistence.
_Avoid_: Command pipe, workflow chain, task runner

**Asset Resolver**:
The centralized, externalized asset resolution module (`ether.registry.assets`) that resolves wordlist specs and macro tokens across direct paths, `$ETHER_WORDLISTS_DIR`, system SecLists, and the embedded `minimal.txt` fallback.
_Avoid_: Wordlist loader, dictionary helper, seed script

**Write Queue Worker**:
A decoupled background serialization worker (`WriteQueue`) managing an async operation queue with exact-ownership reverse PIK lookup and transaction batching to ensure deadlock-free SQLite WAL writes.
_Avoid_: Write thread, database queue, batch runner

**Vector Index Engine**:
A modular subsystem (`VectorIndex`) encapsulating `sqlite-vec` extension loading, `vec_findings` virtual table lifecycle, batch embeddings, and cosine similarity queries.
_Avoid_: Vector helper, embedding module, search wrapper




