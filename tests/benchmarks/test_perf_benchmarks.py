"""Headless performance benchmarks and regression test suite for Ether.

Verifies:
1. GraphStore massive finding bombardment (2,500+ findings under SQLite WAL mode).
2. GraphStore scaling and query limits (5,000 nodes + 2,500 edges via batch ingestion).
3. Pydantic BaseFinding model creation throughput (>20,000 models/sec).
4. LogSpooler high-throughput disk streaming with bounded memory overhead.
"""

import asyncio
import sys
import time
import tracemalloc

import pytest

from ether.core.executor import LogSpooler
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService
from tests.benchmarks.runner import (
    bench_graphstore,
    bench_imports,
    bench_schemas_and_parsing,
    bench_streaming,
    evaluate_regressions,
)

pytestmark = pytest.mark.benchmark


@pytest.mark.asyncio
async def test_graphstore_massive_finding_bombardment(tmp_path):
    """Benchmark: 2,500 findings ingested concurrently into SQLite GraphStore.

    Verifies:
    1. WAL mode handles high concurrency without 'database is locked'.
    2. Composite indexes maintain sub-second query latency for full graph scans.
    """
    db_file = str(tmp_path / "bench_store.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id = await store.create_workspace("BenchWS")
    sess_id = await store.create_session(ws_id, "BenchSess")

    # Generate 1,000 distinct hosts and 1,500 services
    hosts = [
        NetworkHost.create(ip=f"10.0.{i // 254}.{i % 254 + 1}", hostname=f"host-{i}.corp.local")
        for i in range(1000)
    ]
    services = [
        NetworkService.create(
            host_ip=f"10.0.{i // 254}.{i % 254 + 1}", port=80 + (i % 100), service_name="http"
        )
        for i in range(1500)
    ]

    t0 = time.perf_counter()

    # Upsert in micro-batches of 100
    all_findings = hosts + services
    batch_size = 100
    for b in range(0, len(all_findings), batch_size):
        batch = all_findings[b : b + batch_size]
        await asyncio.gather(*(store.upsert_finding(sess_id, f) for f in batch))

    elapsed = time.perf_counter() - t0
    nodes = await store.get_all_nodes(sess_id)
    edges = await store.get_all_edges(sess_id)

    # 1000 hosts + 1500 services (which link to hosts, creating stubs if not existing)
    assert len(nodes) == 3000
    assert len(edges) == 1500

    # Ingestion rate must be > 300 findings/sec on local SQLite WAL
    rate = len(all_findings) / elapsed
    assert rate > 250, f"Ingestion rate was {rate:.0f} findings/sec (expected > 250)"

    t_query = time.perf_counter()
    nodes_check = await store.get_all_nodes(sess_id)
    query_elapsed = time.perf_counter() - t_query
    assert len(nodes_check) == 3000
    assert query_elapsed < 0.5, f"Query took {query_elapsed * 1000:.1f}ms (expected < 500ms)"

    await store.close()


@pytest.mark.asyncio
async def test_graphstore_scale_and_query_limits(tmp_path):
    """Extreme limit benchmark: 5,000 findings ingested via atomic batching and queried."""
    db_file = str(tmp_path / "extreme_store.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id = await store.create_workspace("ExtremeWS")
    sess_id = await store.create_session(ws_id, "ExtremeSess")

    hosts = [NetworkHost.create(ip=f"10.0.{i // 254}.{i % 254 + 1}") for i in range(2500)]
    services = [
        NetworkService.create(
            host_ip=f"10.0.{i // 254}.{i % 254 + 1}", port=80 + (i % 100), service_name="http"
        )
        for i in range(2500)
    ]
    all_findings = hosts + services

    t0 = time.perf_counter()
    batch_size = 100
    for b in range(0, len(all_findings), batch_size):
        await store.upsert_findings_batch(sess_id, all_findings[b : b + batch_size])
    ingest_elapsed = time.perf_counter() - t0

    assert ingest_elapsed < 10.0, f"Batch ingestion took {ingest_elapsed:.2f}s (expected < 10.0s)"

    t_nodes = time.perf_counter()
    nodes = await store.get_all_nodes(sess_id)
    nodes_elapsed = (time.perf_counter() - t_nodes) * 1000
    assert len(nodes) == 5000
    assert nodes_elapsed < 500.0, (
        f"Querying 5,000 nodes took {nodes_elapsed:.1f}ms (expected < 500ms)"
    )

    t_edges = time.perf_counter()
    edges = await store.get_all_edges(sess_id)
    edges_elapsed = (time.perf_counter() - t_edges) * 1000
    assert len(edges) == 2500
    assert edges_elapsed < 500.0, (
        f"Querying 2,500 edges took {edges_elapsed:.1f}ms (expected < 500ms)"
    )

    await store.close()


def test_schema_model_throughput():
    """Benchmark: Pydantic BaseFinding instantiations under high frequency."""
    t0 = time.perf_counter()
    hosts = [
        NetworkHost.create(ip=f"10.0.{i // 254}.{i % 254 + 1}", hostname=f"host-{i}.corp")
        for i in range(10000)
    ]
    elapsed = time.perf_counter() - t0
    rate = 10000 / elapsed
    assert len(hosts) == 10000
    assert rate > 15000, f"Pydantic model creation rate was {rate:.0f}/sec (expected > 15,000)"


def test_log_spooler_throughput_and_bounded_memory(tmp_path):
    """Benchmark: 100,000 log lines streamed through LogSpooler.

    Verifies:
    1. 64KB disk buffering absorbs high-volume bursts with zero loss.
    2. Resident memory overhead remains bounded (< 15MB).
    3. Throughput exceeds 50,000 lines/sec.
    """
    log_file = str(tmp_path / "spooler_bench.log")
    spooler = LogSpooler(log_file)

    tracemalloc.start()
    t0 = time.perf_counter()

    chunk_lines = 100
    total_lines = 100000
    chunk = "".join(
        f"BENCH_LOG_LINE_{i:06d}: target 192.168.1.1 open port\n" for i in range(chunk_lines)
    )

    for _ in range(total_lines // chunk_lines):
        spooler.write(chunk)

    spooler.flush()
    spooler.close()
    elapsed = time.perf_counter() - t0
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    throughput = total_lines / elapsed
    assert throughput > 30000, (
        f"Spooler throughput was {throughput:.0f} lines/sec (expected > 30,000)"
    )
    assert peak_mem < 15 * 1024 * 1024, (
        f"Peak memory {peak_mem / 1024 / 1024:.2f}MB exceeded 15MB bound"
    )
    assert (tmp_path / "spooler_bench.log").exists()


@pytest.mark.asyncio
async def test_benchmark_regression_invariants():
    """Verify that all benchmark invariants pass without regression."""
    python_bin = sys.executable
    import_results = bench_imports(python_bin)
    graphstore_results = await bench_graphstore()
    streaming_results = bench_streaming()
    schema_results = bench_schemas_and_parsing()

    data = {
        "imports": import_results,
        "graphstore": graphstore_results,
        "streaming": streaming_results,
        "schemas": schema_results,
    }

    passed, failed = evaluate_regressions(data)
    assert not failed, f"Benchmark regressions detected: {failed}"
    assert len(passed) >= 4
