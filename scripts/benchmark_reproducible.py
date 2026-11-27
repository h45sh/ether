"""Reproducible benchmark harness capturing environment provenance, workload, and variance."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import statistics
import subprocess
import time
from typing import Any, Dict, List

from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        )
        return out.strip()
    except Exception:
        return "unknown"


async def _run_batch_upsert_trial(batch_size: int = 200) -> float:
    store = GraphStore(":memory:")
    await store.initialize()
    ws = await store.create_workspace("bench-ws")
    sess = await store.create_session(ws, "bench-sess")
    findings = [NetworkHost.create(ip=f"10.0.{i // 250}.{i % 250 + 1}") for i in range(batch_size)]

    t0 = time.perf_counter()
    try:
        await store.upsert_findings_batch(sess, findings)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
    finally:
        await store.close()
    return elapsed_ms


def run_benchmark(iterations: int = 5, batch_size: int = 200) -> Dict[str, Any]:
    """Run reproducible in-memory WriteQueue + GraphStore batch benchmark."""
    samples_ms: List[float] = [
        asyncio.run(_run_batch_upsert_trial(batch_size=batch_size)) for _ in range(iterations)
    ]
    samples_sorted = sorted(samples_ms)
    p95_idx = min(len(samples_sorted) - 1, int(0.95 * len(samples_sorted)))

    return {
        "provenance": {
            "git_commit": _git_commit(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "workload": {
            "name": "graphstore_write_queue_batch_upsert",
            "iterations": iterations,
            "batch_size": batch_size,
        },
        "metrics_ms": {
            "samples": [round(s, 3) for s in samples_ms],
            "mean": round(statistics.mean(samples_ms), 3),
            "stdev": round(statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0, 3),
            "min": round(min(samples_ms), 3),
            "p95": round(samples_sorted[p95_idx], 3),
        },
    }


if __name__ == "__main__":
    report = run_benchmark()
    print(json.dumps(report, indent=2))
