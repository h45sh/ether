# 02: Deterministic State Decay Engine & Stale Query Filtering

**What to build:**
Implement `reconcile_state_decay(session_id: str, now: Optional[datetime] = None) -> Dict[str, Any]` in `src/ether/graph/store.py` to evaluate temporal state decay deterministically without background timers. Identify nodes where `now - last_seen_at > ttl_seconds`. If a node exhibits address or presence oscillations $\ge 2$ within its active window, transition it to `flapping`; otherwise transition it to `stale`. Update `GraphStore.get_all_nodes()` to filter out `stale` nodes by default unless `include_stale=True`. Implement `prune_stale_nodes(session_id: str, max_age_seconds: int = 604800) -> int` for permanent garbage collection. Add unit tests in `tests/unit/test_graph_decay.py`.

**Blocked by:** 01: Database DDL Schema Extensions & BaseFinding Model Update

**Status:** completed

- [x] Implement `GraphStore.reconcile_state_decay(session_id, now=None)` with deterministic decay logic
- [x] Implement flapping heuristic ($\ge 2$ oscillations within active TTL window)
- [x] Update `GraphStore.get_all_nodes()` with `include_stale: bool = False` filtering
- [x] Implement `GraphStore.prune_stale_nodes(session_id, max_age_seconds)`
- [x] Write unit tests in `tests/unit/test_graph_decay.py` verifying state transitions with simulated timestamps
