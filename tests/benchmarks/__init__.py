"""Ether Performance Benchmarks & Limits Suite."""

from tests.benchmarks.runner import (
    async_main,
    bench_graphstore,
    bench_imports,
    bench_schemas_and_parsing,
    bench_streaming,
    evaluate_regressions,
    render_markdown,
)

__all__ = [
    "async_main",
    "bench_graphstore",
    "bench_imports",
    "bench_schemas_and_parsing",
    "bench_streaming",
    "evaluate_regressions",
    "render_markdown",
]
