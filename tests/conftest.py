"""Pytest configuration and global canonical fixtures for Ether."""

import os
import sys
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List

import pytest

# Ensure real repo src/ is on python path regardless of whether running normally or under mutmut isolation
p = Path(__file__).resolve()
if "mutants" in p.parts:
    idx = p.parts.index("mutants")
    repo_root = Path(*p.parts[:idx])
    mutants_root = Path(*p.parts[: idx + 1])
    sys.path.insert(0, str(repo_root / "src"))
    sys.path.insert(0, str(mutants_root / "src"))
else:
    repo_root = p.parent.parent
    repo_src = str(repo_root / "src")
    if repo_src not in sys.path:
        sys.path.insert(0, repo_src)

# Ensure Hypothesis persists its database and caches strictly inside tests/.hypothesis
try:
    import hypothesis.configuration

    hypothesis.configuration.set_hypothesis_home_dir(Path(__file__).parent / ".hypothesis")
except ImportError:
    pass

from ether.core.session import CommandRunner

# ExplainerBackend
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


@pytest.fixture(autouse=True)
def isolate_ether_data_dir(tmp_path, monkeypatch):
    """Automatically isolate all tests to an isolated temporary ETHER_DATA_DIR.

    This ensures test runs never alter or pollute the user's real ~/.ether directory.
    """
    test_data_dir = str(tmp_path / ".ether_test")
    monkeypatch.setenv("ETHER_DATA_DIR", test_data_dir)
    if "ETHER_PLUGIN_TRUST_MODE" not in os.environ:
        monkeypatch.setenv("ETHER_PLUGIN_TRUST_MODE", "dev")
    return test_data_dir


@pytest.fixture
async def in_memory_store() -> AsyncIterator[GraphStore]:
    """Provide an initialized in-memory GraphStore with automatic closing."""
    store = GraphStore(":memory:")
    await store.initialize()
    try:
        yield store
    finally:
        await store.close()


class FakeCommandRunner(CommandRunner):
    """In-memory command runner simulating execution without real subprocesses."""

    def __init__(self, stdout_lines: List[str] = None):
        self.stdout_lines = stdout_lines or ["Starting scan...", "Host is up (0.001s latency)."]
        self.killed = False

    async def run(
        self,
        cmd: List[str],
        env: Dict[str, str],
        cwd: str,
        on_chunk: Any,
        is_shell: bool = False,
    ) -> int:
        for line in self.stdout_lines:
            await on_chunk(line + "\n")
        return 0

    async def kill(self) -> None:
        self.killed = True


@pytest.fixture
def fake_command_runner() -> FakeCommandRunner:
    """Fixture providing a fast in-memory command runner."""
    return FakeCommandRunner()


@pytest.fixture
def sample_host() -> NetworkHost:
    """Standard NetworkHost finding fixture."""
    return NetworkHost.create(ip="10.20.30.40")
