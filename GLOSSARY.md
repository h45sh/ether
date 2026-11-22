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

