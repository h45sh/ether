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

---

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

**Write Queue Worker**:
A decoupled background serialization worker (`WriteQueueWorker`) managing an async operation queue with adaptive transaction batching (25ms window, up to 50 operations) to ensure deadlock-free SQLite WAL writes.
_Avoid_: Write thread, database queue, batch runner

**Vector Index Engine**:
A modular subsystem (`VectorIndex`) encapsulating `sqlite-vec` extension loading, `vec_findings` virtual table lifecycle, batch embeddings, and cosine similarity queries.
_Avoid_: Vector helper, embedding module, search wrapper

**Byte-Bounded Ring Buffer**:
A memory-capped streaming buffer (`ByteBoundedRingBuffer`) in `ExecutionSession` that evicts oldest chunks when total buffered bytes exceed 2 MB or chunk count exceeds 5,000, guaranteeing <10 MB RSS overhead per active job.
_Avoid_: Unbounded buffer, raw deque

**Containerized Tool Runner**:
An execution supervisor module (`ContainerizedToolRunner`) that transparently falls back to an isolated OCI container (`podman`/`docker`) when a required security binary is absent from the host `$PATH`.
_Avoid_: Docker wrapper, container shim

**Raw Network Governor**:
A network execution module (`RawNetworkGovernor`) that performs asynchronous TCP SYN sweeps using ambient `CAP_NET_RAW` capabilities, automatically falling back to non-blocking `asyncio.open_connection` pools when raw sockets are unavailable.
_Avoid_: Port scanner, raw socket helper

**Stream Recovery Engine**:
A parser-pipeline module (`StreamRecoveryEngine`) that salvages valid JSON/XML entities from truncated or timed-out scanner output buffers rather than discarding partial findings.
_Avoid_: Regex fallback, error ignorer

**Storage Lifecycle Manager**:
A background filesystem module (`StorageLifecycleManager`) that enforces configurable disk quotas and Zstandard (`zstd`) compression on historical console logs while preserving `ForensicLogManager` SHA-256 audit chains.
_Avoid_: Log rotator, cleanup cron

**Adaptive Volatility Scoring**:
A `TemporalDecayEngine` mechanism that dynamically scales entity TTL windows using a historical flapping coefficient ($V_n \in [0.1, 1.0]$) so ephemeral cloud containers decay faster than stable hosts.
_Avoid_: Static TTL, fixed expiry


