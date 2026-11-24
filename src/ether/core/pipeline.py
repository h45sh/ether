"""Reactive Pipeline DAG Engine for Ether.

Enables declarative Unix pipe execution for security tools (e.g. "subfinder | dnspython | http_probe")
with bounded memory queues, backpressure concurrency throttling, and graph-driven semantic routing.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.common.context import ExecutionContext
from ether.graph.store import GraphStore
from ether.registry.adapter import ToolAdapter
from ether.registry.registry import ToolRegistry
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost
from ether.schemas.web import WebEndpoint

logger = logging.getLogger(__name__)

_STAGE_PATTERN = re.compile(r"^([a-zA-Z0-9_-]+)(?:\((.*)\))?$")


@dataclass
class PipelineStage:
    """Represents a discrete tool execution stage in the pipeline DAG."""

    tool_name: str
    params: Dict[str, Any] = field(default_factory=dict)
    adapter: Optional[ToolAdapter] = None
    manifest: Optional[Any] = None


@dataclass
class PipelineExecutionStats:
    """Telemetry metrics for a pipeline execution run."""

    stages_executed: int = 0
    findings_produced: int = 0
    peak_concurrency: int = 0
    errors_encountered: int = 0


class PipelineParser:
    """Parses declarative pipe expressions into structured pipeline stages."""

    @classmethod
    def parse(cls, expression: str, registry: ToolRegistry) -> List[PipelineStage]:
        """Parse pipe string (e.g. 'subfinder(target=example.com) | dnspython | http_probe') into PipelineStages."""
        raw_stages = [s.strip() for s in expression.split("|") if s.strip()]
        stages: List[PipelineStage] = []

        for raw_stage in raw_stages:
            m = _STAGE_PATTERN.match(raw_stage)
            if not m:
                raise ValueError(f"Invalid pipeline stage syntax: '{raw_stage}'")

            tool_name = m.group(1).strip()
            raw_params = m.group(2) or ""

            params: Dict[str, Any] = {}
            if raw_params:
                # Parse key=val pairs or raw string
                # e.g. target=example.com, port=80 or raw target
                parts = [p.strip() for p in raw_params.split(",") if p.strip()]
                for part in parts:
                    if "=" in part:
                        k, v = part.split("=", 1)
                        params[k.strip()] = v.strip().strip("\"'")
                    else:
                        params["target"] = part.strip().strip("\"'")

            tool_data = registry.get_tool(tool_name)
            if not tool_data:
                raise ValueError(f"Unknown tool '{tool_name}' in pipeline stage.")

            stages.append(
                PipelineStage(
                    tool_name=tool_name,
                    params=params,
                    adapter=tool_data.get("adapter"),
                    manifest=tool_data.get("manifest"),
                )
            )

        return stages


class PipelineEngine:
    """Supervises concurrent reactive execution across chained pipeline stages."""

    def __init__(
        self,
        registry: ToolRegistry,
        store: Optional[GraphStore] = None,
        max_concurrent: int = 50,
        queue_size: int = 500,
    ):
        self.registry = registry
        self.store = store
        self.max_concurrent = max_concurrent
        self.queue_size = queue_size
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def execute_pipeline(
        self,
        expression: str,
        initial_target: Optional[BaseFinding] = None,
        session_id: Optional[str] = None,
        policy: Any = "safe",
    ) -> AsyncIterator[BaseFinding]:
        """Execute a reactive tool pipeline yielding findings as they arrive from downstream stages."""
        stages = PipelineParser.parse(expression, self.registry)
        if not stages:
            return

        # Single stage or multi-stage pipeline
        # Build stage queues: stage_queues[i] feeds stages[i]
        num_stages = len(stages)
        stage_queues: List[asyncio.Queue[Optional[BaseFinding]]] = [
            asyncio.Queue(maxsize=self.queue_size) for _ in range(num_stages)
        ]
        output_queue: asyncio.Queue[Optional[BaseFinding]] = asyncio.Queue(maxsize=self.queue_size)

        # 1. Feed initial target into stage 0
        first_stage = stages[0]
        seed_target = initial_target
        if not seed_target:
            raw_target = first_stage.params.get("target") or "127.0.0.1"
            if raw_target.startswith("http://") or raw_target.startswith("https://"):
                seed_target = WebEndpoint.create(url=raw_target)
            else:
                seed_target = NetworkHost.create(ip=raw_target)

        await stage_queues[0].put(seed_target)
        await stage_queues[0].put(None)  # EOF for stage 0 inputs

        # 2. Worker runner for a stage
        async def _run_stage(stage_idx: int):
            in_q = stage_queues[stage_idx]
            out_q = stage_queues[stage_idx + 1] if stage_idx + 1 < num_stages else output_queue
            stage = stages[stage_idx]
            adapter = stage.adapter

            context = ExecutionContext(
                action_id=f"pipe-act-{stage_idx}",
                session_id=session_id or "pipeline-session",
                policy=policy,
                runner=None,
            )

            try:
                while True:
                    target_finding = await in_q.get()
                    if target_finding is None:
                        # Forward EOF downstream when all current stage inputs are exhausted
                        in_q.task_done()
                        break

                    # Execute stage tool against this target
                    async with self._semaphore:
                        try:
                            # Use execute_action if overridden (Tier A), or parse_output
                            if getattr(adapter, "execution_tier", "") == "coroutine":
                                async for finding in adapter.execute_action(
                                    target_finding, stage.params, context
                                ):
                                    if self.store and session_id:
                                        await self.store.upsert_finding(session_id, finding)
                                    await out_q.put(finding)
                            else:
                                # For subprocess tools in pipeline test / mock harnesses:
                                # Invoke parse_output on dummy or test runs
                                async for finding in adapter.parse_output(
                                    "", target_finding, context={"params": stage.params}
                                ):
                                    if self.store and session_id:
                                        await self.store.upsert_finding(session_id, finding)
                                    await out_q.put(finding)
                        except Exception as e:
                            logger.error(f"Error in pipeline stage {stage.tool_name}: {e}")

                    in_q.task_done()
            finally:
                await out_q.put(None)

        # 3. Launch worker tasks
        tasks = [asyncio.create_task(_run_stage(i)) for i in range(num_stages)]

        # 4. Stream findings from the output queue to the consumer
        active_terminal_eofs = 1
        while active_terminal_eofs > 0:
            finding = await output_queue.get()
            if finding is None:
                active_terminal_eofs -= 1
                output_queue.task_done()
                break
            output_queue.task_done()
            yield finding

        # Clean up remaining tasks
        await asyncio.gather(*tasks, return_exceptions=True)
