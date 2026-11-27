"""Async serialization queue and exact-ownership batch commit worker for SQLite writes."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("ether.graph.write_queue")

# Type alias: (function, args, kwargs, future, is_upsert, transactional)
WriteTask = Tuple[
    Callable[..., Any],
    Tuple[Any, ...],
    dict[str, Any],
    asyncio.Future[Any],
    bool,
    bool,
]


@dataclass(frozen=True)
class UpsertResult:
    """Exact per-caller finding upsert result with reverse PIK lookup."""

    node_ids: List[str]
    unique_node_ids: List[str]
    parent_nodes: Dict[str, tuple] = field(default_factory=dict)
    assoc_nodes: Dict[str, tuple] = field(default_factory=dict)
    pik_to_node_id: Dict[str, str] = field(default_factory=dict)


def _pik_lookup_key(finding: Any) -> str:
    """Compute a deterministic lookup key for a finding's Primary Identity Key."""
    compute_fn = getattr(finding, "compute_node_id", None)
    if callable(compute_fn):
        return str(compute_fn())
    schema_type = getattr(finding, "schema_type", "")
    pik = getattr(finding, "pik", {}) or {}
    return f"{schema_type}:{json.dumps(pik, sort_keys=True, separators=(',', ':'))}"


class WriteQueue:
    """Dedicated background single-writer worker with exact-ownership batch coalescing."""

    def __init__(
        self,
        get_conn_factory: Callable[[], Any],
        batch_window_seconds: float = 0.001,
        max_batch_size: int = 500,
    ) -> None:
        self._get_conn_factory = get_conn_factory
        self._batch_window = batch_window_seconds
        self._max_batch_size = max_batch_size
        self._queue: Optional[asyncio.Queue[WriteTask]] = None
        self._task: Optional[asyncio.Task[None]] = None
        self._closed = False
        self._closing = False

    @property
    def queue(self) -> Optional[asyncio.Queue[WriteTask]]:
        """Return the underlying asyncio Queue instance."""
        return self._queue

    @property
    def task(self) -> Optional[asyncio.Task[None]]:
        """Return the underlying worker asyncio Task."""
        return self._task

    def ensure_started(self) -> None:
        """Ensure the background writer queue and worker task are running."""
        if self._closed or self._closing:
            raise ValueError("Cannot operate on a closed database.")
        if self._queue is None:
            self._queue = asyncio.Queue()
            self._task = asyncio.create_task(self._writer_loop())

    async def enqueue_upsert(
        self,
        session_id: str,
        findings: Sequence[Any],
        action_id: Optional[str] = None,
        upsert_fn: Optional[Callable[..., Any]] = None,
    ) -> UpsertResult:
        """Serialize a finding batch upsert and return exact per-caller node ownership."""
        if upsert_fn is None:
            raise ValueError("upsert_fn must be provided for enqueue_upsert.")
        if self._closed or self._closing:
            raise ValueError("Cannot operate on a closed database.")
        self.ensure_started()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[UpsertResult] = loop.create_future()
        assert self._queue is not None
        await self._queue.put(
            (upsert_fn, (session_id, list(findings), action_id), {}, fut, True, True)
        )
        return await fut

    async def enqueue_mutation(
        self,
        operation_callable: Callable[..., Any],
        *args: Any,
        transactional: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Serialize an arbitrary SQLite mutation through the single-writer worker."""
        if self._closed or self._closing:
            raise ValueError("Cannot operate on a closed database.")
        self.ensure_started()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        assert self._queue is not None
        await self._queue.put((operation_callable, args, kwargs, fut, False, transactional))
        return await fut

    async def enqueue(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Enqueue a transactional write operation on the serialized writer."""
        return await self.enqueue_mutation(func, *args, transactional=True, **kwargs)

    async def _writer_loop(self) -> None:
        """Background worker loop pulling and batching write operations."""
        while True:
            if self._closed and (self._queue is None or self._queue.empty()):
                break
            try:
                if self._queue is None:
                    break
                try:
                    first_op = await asyncio.wait_for(self._queue.get(), timeout=0.05)
                except asyncio.TimeoutError:
                    if self._closing and (self._queue is None or self._queue.empty()):
                        break
                    continue

                batch = [first_op]
                if len(batch) < self._max_batch_size and not self._closed:
                    await asyncio.sleep(0)
                while len(batch) < self._max_batch_size:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                await self._process_write_batch(batch)

            except asyncio.CancelledError:
                if self._queue:
                    remaining_ops = []
                    while not self._queue.empty():
                        try:
                            remaining_ops.append(self._queue.get_nowait())
                        except Exception:
                            break
                    if remaining_ops:
                        await self._process_write_batch(remaining_ops)
                break
            except Exception as e:
                logger.error(f"Error in GraphStore writer loop: {e}", exc_info=True)
                await asyncio.sleep(0.01)

    async def _process_write_batch(self, batch: List[WriteTask]) -> None:
        """Execute transactional and non-transactional serialized operations."""
        tx_batch = [item for item in batch if item[5]]
        non_tx_batch = [item for item in batch if not item[5]]

        if tx_batch:
            await self._execute_tx_batch(tx_batch)

        for func, args, kwargs, fut, _is_upsert, _tx in non_tx_batch:
            if fut.cancelled():
                if self._queue:
                    self._queue.task_done()
                continue
            try:
                async with self._get_conn_factory() as db:
                    res = await func(db, *args, **kwargs)
                if not fut.cancelled() and not fut.done():
                    fut.set_result(res)
            except Exception as ex:
                if not fut.cancelled() and not fut.done():
                    fut.set_exception(ex)
            finally:
                if self._queue:
                    self._queue.task_done()

    async def _execute_tx_batch(self, batch: List[WriteTask]) -> None:
        """Execute a batch of transactional writes inside a single BEGIN IMMEDIATE transaction."""
        async with self._get_conn_factory() as db:
            try:
                if not db.in_transaction:
                    await db.execute("BEGIN IMMEDIATE")
            except Exception as begin_err:
                for _, _, _, fut, _, _ in batch:
                    if not fut.cancelled() and not fut.done():
                        fut.set_exception(begin_err)
                for _ in batch:
                    if self._queue:
                        self._queue.task_done()
                return

            results: List[Tuple[asyncio.Future[Any], Any, Optional[Exception]]] = []
            upserts: List[WriteTask] = []
            others: List[WriteTask] = []

            for item in batch:
                func, _args, _kwargs, fut, is_upsert, _tx = item
                if (
                    is_upsert or getattr(func, "__name__", "") == "_raw_upsert_findings_batch"
                ) and not fut.cancelled():
                    upserts.append(item)
                else:
                    others.append(item)

            if upserts:
                from collections import defaultdict

                grouped = defaultdict(list)
                for func, args, kwargs, fut, is_upsert, _tx in upserts:
                    s_id = args[0] if len(args) > 0 else kwargs.get("session_id")
                    f_list = args[1] if len(args) > 1 else kwargs.get("findings", [])
                    a_id = args[2] if len(args) > 2 else kwargs.get("action_id")
                    grouped[(func, s_id, a_id)].append((list(f_list), fut, is_upsert))

                for (func, s_id, a_id), items in grouped.items():
                    combined: List[Any] = []
                    for f_list, _fut, _is_upsert in items:
                        combined.extend(f_list)
                    try:
                        res = await func(db, s_id, combined, a_id)
                        all_nids, _u_nids, parent_nodes, assoc_nodes = res

                        if len(all_nids) == len(combined):
                            offset = 0
                            for f_list, fut, is_upsert in items:
                                count = len(f_list)
                                caller_nids = list(all_nids[offset : offset + count])
                                offset += count
                                if fut.cancelled() or fut.done():
                                    continue
                                caller_unique: List[str] = []
                                seen_caller: set[str] = set()
                                caller_pik_map: Dict[str, str] = {}
                                for f_obj, nid in zip(f_list, caller_nids, strict=True):
                                    caller_pik_map[_pik_lookup_key(f_obj)] = nid
                                    if nid not in seen_caller:
                                        seen_caller.add(nid)
                                        caller_unique.append(nid)

                                if is_upsert:
                                    caller_res: Any = UpsertResult(
                                        node_ids=caller_nids,
                                        unique_node_ids=caller_unique,
                                        parent_nodes=parent_nodes,
                                        assoc_nodes=assoc_nodes,
                                        pik_to_node_id=caller_pik_map,
                                    )
                                else:
                                    caller_res = (
                                        caller_nids,
                                        caller_unique,
                                        parent_nodes,
                                        assoc_nodes,
                                    )
                                results.append((fut, caller_res, None))
                        else:
                            # Fallback if upsert_fn returned deduplicated IDs rather than 1:1 per input
                            pik_to_nid: Dict[str, str] = {}
                            for finding_obj, nid in zip(combined, all_nids, strict=False):
                                pik_to_nid[_pik_lookup_key(finding_obj)] = nid

                            for f_list, fut, is_upsert in items:
                                if fut.cancelled() or fut.done():
                                    continue
                                caller_nids = []
                                caller_unique = []
                                seen_caller = set()
                                caller_pik_map = {}
                                for f_obj in f_list:
                                    key = _pik_lookup_key(f_obj)
                                    nid = pik_to_nid.get(key, "")
                                    if nid:
                                        caller_nids.append(nid)
                                        caller_pik_map[key] = nid
                                        if nid not in seen_caller:
                                            seen_caller.add(nid)
                                            caller_unique.append(nid)

                                if is_upsert:
                                    caller_res = UpsertResult(
                                        node_ids=caller_nids,
                                        unique_node_ids=caller_unique,
                                        parent_nodes=parent_nodes,
                                        assoc_nodes=assoc_nodes,
                                        pik_to_node_id=caller_pik_map,
                                    )
                                else:
                                    caller_res = (
                                        caller_nids,
                                        caller_unique,
                                        parent_nodes,
                                        assoc_nodes,
                                    )
                                results.append((fut, caller_res, None))
                    except Exception as ex:
                        for _f_list, fut, _is_upsert in items:
                            if not fut.cancelled() and not fut.done():
                                results.append((fut, None, ex))

            for func, args, kwargs, fut, _is_upsert, _tx in others:
                if fut.cancelled():
                    results.append((fut, None, None))
                    continue
                try:
                    res = await func(db, *args, **kwargs)
                    results.append((fut, res, None))
                except Exception as ex:
                    results.append((fut, None, ex))

            try:
                await db.commit()
            except Exception as commit_err:
                if db.in_transaction:
                    try:
                        await db.rollback()
                    except Exception:
                        pass
                for fut, _, _ in results:
                    if not fut.cancelled() and not fut.done():
                        fut.set_exception(commit_err)
                for _ in batch:
                    if self._queue:
                        self._queue.task_done()
                return

            for fut, res, err in results:
                if not fut.cancelled() and not fut.done():
                    if err is not None:
                        fut.set_exception(err)
                    else:
                        fut.set_result(res)

            for _ in batch:
                if self._queue:
                    self._queue.task_done()

    async def close(self) -> None:
        """Gracefully drain the write queue and stop the background task."""
        self._closing = True
        if self._queue is not None:
            await self._queue.join()

        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

        self._closed = True


WriteQueueWorker = WriteQueue
