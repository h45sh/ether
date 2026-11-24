"""Tests for GraphStore high-concurrency async write queue daemon and read pool."""

import asyncio
from pathlib import Path

import pytest

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost, NetworkService


@pytest.mark.asyncio
async def test_concurrent_writes_50_coroutines(tmp_path: Path):
    """Verify 50+ concurrent coroutines can simultaneously emit findings without lock errors."""
    db_file = str(tmp_path / "concurrent_test.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_workspace_session("TestWS", "TestSess")

    num_concurrent = 60

    async def emit_finding(idx: int):
        finding = NetworkHost.create(
            ip=f"10.0.0.{idx}",
            hostname=f"host-{idx}.local",
        )
        return await store.upsert_finding(sess_id, finding)

    # Launch 60 parallel coroutines emitting findings simultaneously
    tasks = [asyncio.create_task(emit_finding(i)) for i in range(1, num_concurrent + 1)]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    assert len(results) == num_concurrent

    # Verify all nodes are present in the store
    nodes = await store.get_all_nodes(sess_id)
    assert len(nodes) == num_concurrent

    await store.close()


@pytest.mark.asyncio
async def test_concurrent_reads_during_writes(tmp_path: Path):
    """Verify read queries execute cleanly from the reader pool during high write load."""
    db_file = str(tmp_path / "read_during_write.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_workspace_session("ReadWS", "ReadSess")

    write_done = asyncio.Event()

    async def writer_worker():
        for i in range(1, 40):
            finding = NetworkService.create(
                host_ip="192.168.1.1",
                port=i,
                protocol="tcp",
                service_name=f"svc-{i}",
            )
            await store.upsert_finding(sess_id, finding)
            await asyncio.sleep(0.005)
        write_done.set()

    read_counts = []

    async def reader_worker():
        while not write_done.is_set():
            nodes = await store.get_all_nodes(sess_id)
            read_counts.append(len(nodes))
            await asyncio.sleep(0.01)

    await asyncio.gather(writer_worker(), reader_worker())

    assert len(read_counts) > 0
    # Final count should match 39 services plus host
    final_nodes = await store.get_all_nodes(sess_id)
    assert len(final_nodes) >= 39

    await store.close()


@pytest.mark.asyncio
async def test_graceful_close_drains_pending(tmp_path: Path):
    """Verify GraphStore.close() cleanly drains all pending operations without dropping writes."""
    db_file = str(tmp_path / "drain_test.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id, sess_id = await store.get_or_create_workspace_session("DrainWS", "DrainSess")

    # Queue 20 writes in rapid succession without awaiting immediately
    tasks = []
    for i in range(1, 21):
        finding = NetworkHost.create(
            ip=f"172.16.0.{i}",
            hostname=f"node-{i}.corp",
        )
        tasks.append(asyncio.create_task(store.upsert_finding(sess_id, finding)))

    # Yield so tasks enqueue into write queue
    await asyncio.sleep(0)

    # Close store while writes are being processed by writer queue
    close_task = asyncio.create_task(store.close())
    await asyncio.gather(*tasks, close_task)

    # Reopen database to verify all 20 nodes were durably committed
    reopened = GraphStore(db_file)
    nodes = await reopened.get_all_nodes(sess_id)
    assert len(nodes) == 20
    await reopened.close()
