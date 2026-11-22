# Specification: Epoch 2 Milestone 2.3 — Temporal Graph State Decay & Cryptographic Invariance

## 1. Objective & Scope

Milestone 2.3 deepens Ether's state machine by implementing **Temporal Graph State Decay** and **Invariant Identity Anchoring** in `GraphStore`. This allows Ether to handle container churn, ephemeral IPs, and fast-flux DNS without orphan node pollution, while tracking assets across network reassignments via cryptographic fingerprints.

---

## 2. Architecture & Design Principles

### 2.1 Deterministic Temporal Decay Engine
- State machine transitions:
  - `proposed`: Low-confidence or speculative finding.
  - `confirmed`: Verified finding observed within its `ttl_seconds` threshold.
  - `flapping`: Finding whose address or presence oscillates $\ge 2$ times within its TTL window.
  - `stale`: Finding not re-observed within its `ttl_seconds` threshold.
- Pure evaluation: `store.reconcile_state_decay(session_id, now=None)` computes transitions deterministically with mockable timestamps.
- Zero non-deterministic timers: Decay is evaluated on demand, on queries, and during telemetry diff calculation.

### 2.2 Invariant Identity Anchoring
- Primary Identity Keys (PIK) remain the deterministic observation key (`schema_type` + sorted PIK fields).
- An indexed `anchor_hash` (`<type>:<hash>`) stores persistent cryptographic fingerprints:
  - `tls:<sha256_hex>`: TLS certificate SHA-256 fingerprint.
  - `ssh:<sha256_hex>`: SSH host key fingerprint.
  - `favicon:<hash>`: Web application favicon hash (MurmurHash3 or SHA-256).
  - `soa:<serial>`: DNS zone SOA serial number.
- When a node is upserted with an existing `anchor_hash` on a different IP/host:
  - Create an `anchored_identity` edge connecting the nodes.
  - Transition the old node to `stale`.
  - Telemetry diff reports identity migration rather than an untracked new asset.

### 2.3 Stale Filtering & Garbage Collection
- `store.get_all_nodes(session_id, include_stale=False)` excludes stale nodes from agent context.
- `store.prune_stale_nodes(session_id, max_age_seconds)` allows explicit permanent removal of stale nodes and cascading edges.

---

## 3. Schema & Database Specifications

### 3.1 SQLite DDL (`SCHEMA_DDL`)
```sql
CREATE TABLE IF NOT EXISTS nodes (
    session_id TEXT NOT NULL,
    id TEXT NOT NULL,
    schema_type TEXT NOT NULL,
    pik_json TEXT NOT NULL,
    data_json TEXT NOT NULL,
    status TEXT DEFAULT 'confirmed',
    action_id TEXT,
    created_action_id TEXT,
    observation_count INTEGER DEFAULT 1,
    ttl_seconds INTEGER DEFAULT 3600,
    anchor_hash TEXT,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, id),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_nodes_anchor ON nodes(session_id, anchor_hash);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(session_id, status);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(session_id, last_seen_at);
```

### 3.2 Pydantic BaseFinding Updates (`src/ether/schemas/base.py`)
```python
class BaseFinding(BaseModel):
    ...
    status: Literal["proposed", "confirmed", "flapping", "stale"] = "confirmed"
    ttl_seconds: int = 3600
    anchor_hash: Optional[str] = None
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
```

---

## 4. Telemetry Diff Integration

Action diffs (`GraphTelemetryCompiler.compute_graph_diff`) automatically invoke `reconcile_state_decay()` and report:
```json
{
  "added_nodes": [...],
  "updated_nodes": [
    {
      "id": "da7246ff",
      "new_attributes": { "status": "stale" },
      "previous_attributes": { "status": "confirmed" }
    }
  ],
  "status_breakdown": {
    "confirmed": 12,
    "flapping": 1,
    "stale": 4
  },
  "anchored_migrations": [
    {
      "anchor_hash": "tls:e3b0c442...",
      "from_node_id": "da7246ff",
      "to_node_id": "71a9bf32"
    }
  ],
  "total_delta_count": 3
}
```

---

## 5. Tool Adapter Enhancements

1. **`tools/http_probe`**:
   - Extract peer TLS certificate SHA-256 fingerprint on HTTPS connections (`tls:<fingerprint>`).
   - Extract and hash `/favicon.ico` response (`favicon:<hash>`).
   - Populate `anchor_hash` on yielded `NetworkService` and `WebEndpoint`.

2. **`tools/dnspython`**:
   - Extract SOA serial number (`soa:<serial>`).
   - Set `ttl_seconds` from actual DNS TTL responses.
