# 03: Invariant Identity Anchoring & Cross-IP Migration

**What to build:**
Implement the Invariant Identity Anchoring engine in `src/ether/graph/store.py`. During `upsert_findings_batch()`, when an incoming finding has an `anchor_hash` (e.g. `tls:<sha256>`, `ssh:<sha256>`, `favicon:<hash>`, `soa:<serial>`), check for existing nodes in the session sharing the identical `anchor_hash` but bound to a different network coordinate. If detected, automatically generate an `anchored_identity` relationship edge connecting the old and new nodes, decay the previous node to `stale`, and log the migration event. Update schemas in `src/ether/schemas/` to extract candidate anchor hashes automatically. Write unit tests in `tests/unit/test_identity_anchoring.py`.

**Blocked by:** 01: Database DDL Schema Extensions & BaseFinding Model Update

**Status:** completed

- [x] Implement cross-IP anchor reconciliation logic in `GraphStore.upsert_findings_batch()`
- [x] Automatically wire `anchored_identity` relationship edges when identical anchors are observed on new IPs
- [x] Transition previous location nodes to `stale` upon migration
- [x] Add anchor extraction helpers to `NetworkService`, `WebEndpoint`, and `DnsRecord`
- [x] Write unit tests in `tests/unit/test_identity_anchoring.py` verifying cross-IP migration without duplicate orphan nodes
