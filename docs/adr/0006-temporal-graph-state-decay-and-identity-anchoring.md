# ADR 0006: Temporal Graph State Decay & Cryptographic Identity Anchoring

## Status
Accepted

## Context
In Epoch 1 and Milestone 2.1-2.2, Ether’s deterministic graph model derived entity node IDs strictly from Primary Identity Keys (PIK) (e.g. `schema_type` + `ip` / `port`). While this guarantees mathematical deduplication for static targets, modern attack surfaces are highly dynamic:
1. **Container & Cloud Churn:** Microservices and cloud instances frequently restart, changing IP addresses or ephemeral listening ports. Under pure IP-based PIK derivation, an IP shift causes the entity graph to spawn duplicate orphan nodes while retaining ghost nodes at old IPs.
2. **Fast-Flux DNS & Ephemeral Endpoints:** CDN load balancing, round-robin DNS, and ephemeral services cause nodes to appear, disappear, and oscillate rapidly across actions.
3. **No Temporal Aging:** Nodes previously confirmed in a scan remain permanently `confirmed` in the database forever unless manually purged, polluting agent context with dead assets.

Ether requires:
1. A **deterministic state decay lifecycle** (`proposed` $\to$ `confirmed` $\to$ `flapping` $\to$ `stale`) that models node confidence degradation over time without non-deterministic background timers.
2. **Cryptographic Invariant Anchoring** that decouples logical entity identity from volatile network coordinates by anchoring findings to persistent cryptographic fingerprints (TLS cert SHA-256, SSH host keys, HTTP favicon/ETag hashes).

## Decision
1. **Multi-State Temporal Lifecycle & Deterministic Decay:**
   - Extend `nodes.status` to `proposed | confirmed | flapping | stale`.
   - Update `nodes` table in `SCHEMA_DDL` to store `observation_count`, `ttl_seconds`, `anchor_hash`, and `last_seen_at`.
   - Implement `store.reconcile_state_decay(session_id, now=None)` as a pure deterministic state transition engine:
     - Nodes exceeding `ttl_seconds` without re-observation transition to `stale`.
     - Nodes oscillating presence or address $\ge 2$ times within the active window transition to `flapping`.
     - Nodes actively re-observed reset their TTL window and remain `confirmed`.
   - Reconcile state decay automatically during `GraphTelemetryCompiler.compute_graph_diff()`.

2. **Invariant Identity Anchoring:**
   - Every node retains its deterministic PIK for immediate observation deduplication.
   - When findings contain cryptographic or structural fingerprints (TLS certificate SHA-256, SSH host key fingerprint, HTTP favicon hash, DNS SOA serial), an `anchor_hash` is computed in the format `<type>:<hash>`.
   - During `upsert_findings_batch()`, if an incoming node presents an `anchor_hash` identical to an existing node at a different network coordinate:
     - `GraphStore` automatically creates an `anchored_identity` relationship edge linking the old and new nodes.
     - The previous location decays to `stale`, and the agent diff reflects an entity migration rather than an untracked orphan node.

3. **Stale Query Filtering & Pruning:**
   - Default queries (`store.get_all_nodes()`, MCP `query_graph`, CLI `ether graph list-nodes`) filter out `stale` nodes by default (`include_stale=False`) to minimize agent token usage.
   - Provide `store.prune_stale_nodes(session_id, max_age_seconds)` for explicit garbage collection.

4. **Adapter Ingestion Upgrades:**
   - Update `tools/http_probe` to capture TLS X.509 peer certificate SHA-256 fingerprints on HTTPS endpoints and `/favicon.ico` hashes.
   - Update `tools/dnspython` to capture `SOA` serial numbers and record-level TTLs.

## Consequences
- Prevents graph pollution from ephemeral containers, DHCP rotations, and fast-flux DNS.
- Decreases agent LLM context consumption by hiding stale nodes while preserving historical forensic traceability.
- Eliminates duplicate orphan nodes by cryptographically bridging entities across IP migrations.
- State evaluation remains 100% deterministic with zero flaky background timers or race conditions.
