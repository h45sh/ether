"""Execution context for unified tool execution across coroutines and subprocesses."""

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional


@dataclass
class ExecutionContext:
    """Runtime context passed to ToolAdapter.execute_action."""

    action_id: str
    session_id: str
    policy: str = "safe"
    cwd: str = "."
    env: Optional[Dict[str, str]] = None
    use_shell: bool = False
    shell_path: Optional[str] = None
    timeout_seconds: Optional[int] = None
    runner: Optional[Any] = None
    spool_fn: Optional[Callable[[str, bool], Awaitable[None]]] = None

    async def spool_line(self, line: str, is_error: bool = False) -> None:
        """Stream raw wire or process output text to disk spooler and listeners."""
        if self.spool_fn is not None:
            await self.spool_fn(line, is_error)
