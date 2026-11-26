"""Ether: Reactive process supervisor and graph telemetry engine for security tools."""

from ether.common.exceptions import EtherError
from ether.common.scope import EngagementScope, ScopeValidator
from ether.core.executor import Executor, LogSpooler, sanitize_subprocess_env
from ether.core.session import ExecutionSession
from ether.gateway.gate import ActionGateway, ActionValidationError, GatePolicy
from ether.graph.analytics import GraphAnalyticsEngine
from ether.graph.store import GraphStore
from ether.graph.timeline import ActionTimelineRepository
from ether.graph.write_queue import WriteQueue
from ether.registry.adapter import ToolAdapter
from ether.registry.registry import ToolRegistry
from ether.schemas.base import BaseFinding

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("ether-core")
except (PackageNotFoundError, ImportError):
    __version__ = "0.1.3"

__all__ = [
    "ActionGateway",
    "ActionTimelineRepository",
    "ActionValidationError",
    "BaseFinding",
    "EngagementScope",
    "EtherError",
    "ExecutionSession",
    "Executor",
    "GatePolicy",
    "GraphAnalyticsEngine",
    "GraphStore",
    "LogSpooler",
    "ScopeValidator",
    "ToolAdapter",
    "ToolRegistry",
    "WriteQueue",
    "__version__",
    "sanitize_subprocess_env",
]
