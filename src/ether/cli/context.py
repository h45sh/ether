"""CLI runtime execution context and resource lifecycle management for Ether."""

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Optional

from ether import paths
from ether.config import EtherSettings
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
    settings: EtherSettings = field(default_factory=EtherSettings)

    @classmethod
    def from_args(cls, args) -> "CliContext":
        """Resolve CLI arguments into an immutable runtime context."""
        data_dir_arg = getattr(args, "data_dir", None)
        db_arg = getattr(args, "db", None)
        tools_arg = getattr(args, "tools", None)
        config_arg = getattr(args, "config", None)
        policy_arg = getattr(args, "policy", None)

        cli_overrides: Dict[str, Dict[str, Any]] = {
            "paths": {
                "data_dir": data_dir_arg,
                "db_path": db_arg,
                "tools_dir": tools_arg,
            },
            "gateway": {
                "policy": str(policy_arg).lower() if policy_arg is not None else None,
            },
            "logging": {
                "debug": True if getattr(args, "verbose", False) else None,
            },
        }
        settings = EtherSettings.load(
            data_dir=data_dir_arg,
            config_path=config_arg,
            cli_overrides=cli_overrides,
        )

        data_dir = settings.paths.data_dir or paths.get_default_data_dir()
        db_path = settings.paths.db_path or paths.get_default_db_path(data_dir)
        tools_dir = settings.paths.tools_dir

        is_json = bool(getattr(args, "json", False))
        verbose = bool(getattr(args, "verbose", False)) or settings.logging.debug

        if settings.gateway.policy == "unrestricted":
            policy = GatePolicy.UNRESTRICTED
        else:
            policy = GatePolicy.SAFE

        return cls(
            data_dir=data_dir,
            db_path=db_path,
            tools_dir=tools_dir,
            is_json=is_json,
            verbose=verbose,
            policy=policy,
            settings=settings,
        )

    @asynccontextmanager
    async def open_store(self) -> AsyncIterator[GraphStore]:
        """Context manager guaranteeing initialized GraphStore and clean teardown."""
        store = GraphStore(self.db_path, settings=self.settings)
        await store.initialize()
        try:
            yield store
        finally:
            await store.close()

    def get_registry(self) -> ToolRegistry:
        """Instantiate and load ToolRegistry."""
        registry = ToolRegistry(tools_dir=self.tools_dir, settings=self.settings)
        registry.load_tools()
        return registry
