# Quantitative Invariants & Performance Contracts (Tier 2)

## 1. Runtime Performance Thresholds
- **Cold Application Launch**: $< 300\text{ms}$ cold import time; hard ceiling is **$600\text{ms}$** (`python -c "import ether"`).
- **Process Stream RAM Buffer**: Heap footprint strictly bounded to $\le 10\text{MB}$ via bounded ring buffer (`deque(maxlen=5000)`).
- **Process Stream Throughput**: LogSpooler with 64KB buffering writing directly to disk (`data/logs/{action_id}.log`).
- **GraphStore Ingestion Rate**: Bulk findings ingestion $\ge 2,000\text{ entities/sec}$ (hard CI floor $\ge 1,200\text{ entities/sec}$ under virtualized runners).
- **GraphStore Scale Queries**: 5,000 nodes and 2,500 edges queried in $\le 500\text{ms}$ in SQLite via parameter-bound queries and indexed foreign keys.
- **Offline Vector Engine Latency**: Sub-millisecond execution ($< 0.1\text{ms}$) per text string using 384-dimensional unit-normalized multi-hash projections.

## 2. CI Runner Variance & Benchmark Rules
- **No Microsecond Assertions**: In-memory operations running in 15–35ms on bare metal can take 150–250ms on shared GitHub Actions runners due to multi-tenant CPU contention and virtualized I/O scheduling.
- **Benchmark Threshold Standard**: For operations processing 5,000+ entities, set CI performance bounds to $< 500\text{ms}$. This accommodates hypervisor jitter while reliably catching $O(N^2)$ algorithmic regressions ($> 5,000\text{ms}$).
- **CI Execution Time**: Target $\le 3\text{ minutes}$ per matrix job with optimized uv caching and concurrency cancellation enabled.

## 3. Security, Operational & Release Boundaries
- **Ephemeral Release Authentication**: PyPI and GHCR release jobs use strictly short-lived GitHub Actions OIDC tokens (`id-token: write`); zero long-lived API secrets.
- **Packaging Integrity**: 100% packaged asset verification by building and testing the real distribution wheel artifact (`dist/*.whl`) in CI.
- **SSRF Blocklist Preservation**: `ActionGateway.BLOCKED_TARGETS` must permanently block AWS IMDSv2, Alibaba metadata, IPv4 link-local (`169.254.0.0/16`), and hexadecimal/decimal IP encodings.
- **Subprocess Environment Isolation**: Subprocess spawning must always execute `sanitize_subprocess_env()` to strip API keys, cloud credentials, and SSH handles.
- **Untrusted Output Boundary**: All untrusted scanner output passed to LLMs must be sanitized and enclosed within `<untrusted_scan_output>...</untrusted_scan_output>` tags with tag breakout escaping and strict length bounding (`max_chars=100_000`).
- **Forensic Chain of Custody**: All actions maintain SHA-256 hash-chained `AuditRecord` entries in the session audit manifest, verified via `ether session verify-audit`.
- **Zero Backward Compatibility Debt**: Ether is maintained as a fresh, modern engine. No legacy shims, dead wrappers, or runtime migration loops are retained.

## 4. Testing & Architectural Invariants
- **Fast Pre-Flight Tier 0 (`pytest -m tier0 -q`)**: Must complete in $< 3.0\text{s}$ with zero network calls and zero flakiness.
- **AST Architecture Enforcement**: Zero UI imports, zero `shell=True`, zero `os.system`, zero direct `subprocess` imports in adapters, and zero unparameterized SQL queries (`tests/unit/test_architecture.py`).
- **Adapter Crash-Resilience**: 100% crash immunity across all registered security tool adapters against hostile, malformed ANSI, truncated JSON, and 20k-token fuzz streams (`tests/unit/test_parsers/test_fuzz_all_adapters.py`).
- **Concurrency & Ring Buffer Boundedness**: Zero deadlocks and strict $O(1)$ RAM bounding ($\le 5000$ lines) under streaming loads.
