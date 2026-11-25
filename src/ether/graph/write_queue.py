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
        batch_window_seconds: float = 0.025,
        max_batch_size: int = 50,
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
                loop = asyncio.get_running_loop()
                deadline = loop.time() + self._batch_window

                while len(batch) < self._max_batch_size:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        break
                    try:
                        op = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                        batch.append(op)
                    except asyncio.TimeoutError:
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
        """Execute a batch of write operations in a single atomic transaction."""
        async with self._get_conn_factory() as db:
            results = []
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
                for fut, _, _ in results:
                    if not fut.cancelled() and not fut.done():
                        fut.set_exception(commit_err)
                for _ in batch:
                    if self._queue:
                        self._queue.task_done()
                return

            for fut, res, ex in results:
                if not fut.cancelled() and not fut.done():
                    if ex is not None:
                        fut.set_exception(ex)
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
