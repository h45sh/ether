"""CLI runtime execution context and resource lifecycle management for Ether."""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Optional

from ether import paths
from ether.gateway.gate import GatePolicy
from ether.graph.store import GraphStore
from ether.registry.registry import ToolRegistry

EXIT_SUCCESS = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2
EXIT_MISSING_DEP = 127


@dataclass(frozen=True)
class CliContext:
    """Encapsulates runtime parameters, database paths, and execution policy."""

    data_dir: str
    db_path: str
    tools_dir: Optional[str]
    is_json: bool
    verbose: bool
    policy: GatePolicy

    @classmethod
    def from_args(cls, args) -> "CliContext":
        """Resolve CLI arguments into an immutable runtime context."""
        data_dir_arg = getattr(args, "data_dir", None)
        db_arg = getattr(args, "db", None)
        tools_arg = getattr(args, "tools", None)

        data_dir = data_dir_arg or paths.get_default_data_dir()
        db_path = db_arg or paths.get_default_db_path(data_dir)

        is_json = bool(getattr(args, "json", False))
        verbose = bool(getattr(args, "verbose", False))

        policy_str = getattr(args, "policy", "safe")
        if str(policy_str).lower() == "unrestricted":
            policy = GatePolicy.UNRESTRICTED
        else:
            policy = GatePolicy.SAFE

        return cls(
            data_dir=data_dir,
            db_path=db_path,
            tools_dir=tools_arg,
            is_json=is_json,
            verbose=verbose,
            policy=policy,
        )

    @asynccontextmanager
    async def open_store(self) -> AsyncIterator[GraphStore]:
        """Context manager guaranteeing initialized GraphStore and clean teardown."""
        store = GraphStore(self.db_path)
        await store.initialize()
        try:
            yield store
        finally:
            await store.close()

    def get_registry(self) -> ToolRegistry:
        """Instantiate and load ToolRegistry."""
        registry = ToolRegistry(tools_dir=self.tools_dir)
        registry.load_tools()
        return registry
