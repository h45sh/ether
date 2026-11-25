"""Async serialization queue and batch commit worker for SQLite writes in Ether."""

import asyncio
import logging
from typing import Any, Callable, List, Optional, Tuple

logger = logging.getLogger("ether.graph.write_queue")

# Type alias: (function, args, kwargs, future)
WriteTask = Tuple[Callable[..., Any], Tuple[Any, ...], dict[str, Any], asyncio.Future]


class WriteQueueWorker:
    """Dedicated background single-writer worker with adaptive transaction batching."""

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
        self._task: Optional[asyncio.Task] = None
        self._closed = False
        self._closing = False

    @property
    def queue(self) -> Optional[asyncio.Queue[WriteTask]]:
        """Return the underlying asyncio Queue instance."""
        return self._queue

    @property
    def task(self) -> Optional[asyncio.Task]:
        """Return the underlying worker asyncio Task."""
        return self._task

    def ensure_started(self) -> None:
        """Ensure the background writer queue and worker task are running."""
        if self._closed:
            raise ValueError("Cannot operate on a closed database.")
        if self._queue is None:
            self._queue = asyncio.Queue()
            self._task = asyncio.create_task(self._writer_loop())

    async def enqueue(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Enqueue a write operation to be executed in the batch writer."""
        if self._closed:
            raise ValueError("Cannot operate on a closed database.")
        self.ensure_started()
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        assert self._queue is not None
        await self._queue.put((func, args, kwargs, fut))
        return await fut

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
        """Execute a batch of write operations in a single atomic BEGIN IMMEDIATE transaction."""
        async with self._get_conn_factory() as db:
            try:
                if not db.in_transaction:
                    await db.execute("BEGIN IMMEDIATE")
            except Exception as begin_err:
                for _, _, _, fut in batch:
                    if not fut.cancelled() and not fut.done():
                        fut.set_exception(begin_err)
                for _ in batch:
                    if self._queue:
                        self._queue.task_done()
                return

            results: List[Tuple[asyncio.Future[Any], Any, Optional[Exception]]] = []

            upserts: List[Tuple[Any, Any, Any, asyncio.Future[Any]]] = []
            others: List[WriteTask] = []
            for item in batch:
                func, args, kwargs, fut = item
                if (
                    getattr(func, "__name__", "") == "_raw_upsert_findings_batch"
                    and not fut.cancelled()
                ):
                    upserts.append(item)
                else:
                    others.append(item)

            if len(upserts) > 1:
                from collections import defaultdict

                grouped = defaultdict(list)
                for func, args, kwargs, fut in upserts:
                    s_id = args[0] if len(args) > 0 else kwargs.get("session_id")
                    f_list = args[1] if len(args) > 1 else kwargs.get("findings", [])
                    a_id = args[2] if len(args) > 2 else kwargs.get("action_id")
                    grouped[(func, s_id, a_id)].append((f_list, fut))

                for (func, s_id, a_id), items in grouped.items():
                    combined = []
                    futs_info = []
                    for f_list, fut in items:
                        s = len(combined)
                        combined.extend(f_list)
                        futs_info.append((fut, s, len(combined)))
                    try:
                        res = await func(db, s_id, combined, a_id)
                        all_nids, u_nids, p_nodes, a_nodes = res
                        for fut, s, e in futs_info:
                            if not fut.cancelled() and not fut.done():
                                results.append(
                                    (fut, (all_nids[s:e], u_nids, p_nodes, a_nodes), None)
                                )
                    except Exception as ex:
                        for fut, _, _ in futs_info:
                            if not fut.cancelled() and not fut.done():
                                results.append((fut, None, ex))

                for func, args, kwargs, fut in others:
                    if fut.cancelled():
                        results.append((fut, None, None))
                        continue
                    try:
                        res = await func(db, *args, **kwargs)
                        results.append((fut, res, None))
                    except Exception as ex:
                        results.append((fut, None, ex))
            else:
                for func, args, kwargs, fut in batch:
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
