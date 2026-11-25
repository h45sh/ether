"""Asynchronous tool execution engine."""

import asyncio
import logging
import os
import shlex
import shutil
from collections import deque
from typing import Any, AsyncIterator, Callable, Coroutine, Dict, Optional, Tuple

from ether.common import strip_ansi
from ether.common.forensic_log import LogSpooler
from ether.graph.store import GraphStore
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding

logger = logging.getLogger(__name__)


def sanitize_subprocess_env(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Sanitize environment variables passed to child subprocesses to prevent secret leakage."""
    base_env = env if env is not None else os.environ.copy()
    sensitive_prefixes = (
        "ETHER_",
        "CYGUIDE_",
        "OPENAI_",
        "GROQ_",
        "ANTHROPIC_",
        "OPENROUTER_",
        "GEMINI_",
        "GROK_",
        "MISTRAL_",
        "COHERE_",
        "DEEPSEEK_",
        "PERPLEXITY_",
        "PPLX_",
        "HUGGINGFACE_",
        "HF_",
    )
    sensitive_exact = {
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "API_KEY",
        "SECRET_KEY",
        "PRIVATE_KEY",
        "VAULT_TOKEN",
        "SSH_PRIVATE_KEY",
    }
    return {
        k: v
        for k, v in base_env.items()
        if not any(k.upper().startswith(p) for p in sensitive_prefixes)
        and k.upper() not in sensitive_exact
    }


class StreamTarpitGuard:
    """Detects delay-tarpits (sub-byte trickle) and infinite banner loops."""

    def __init__(self, window_seconds: float = 15.0, min_bytes_per_sec: float = 10.0):
        self.window_seconds = window_seconds
        self.min_bytes_per_sec = min_bytes_per_sec
        self._chunks: deque[Tuple[float, int, int]] = deque()
        self._first_chunk_time: Optional[float] = None
        self._last_finding_time: Optional[float] = None

    def record_finding(self, current_time: float) -> None:
        self._last_finding_time = current_time

    def check_chunk(self, chunk_len: int, chunk_bytes: bytes, current_time: float) -> Tuple[bool, str]:
        """Evaluate incoming stream chunk. Returns (is_tarpit, reason)."""
        if self._first_chunk_time is None:
            self._first_chunk_time = current_time
            self._last_finding_time = current_time

        chunk_hash = hash(chunk_bytes[:256])
        self._chunks.append((current_time, chunk_len, chunk_hash))

        while self._chunks and (current_time - self._chunks[0][0]) > self.window_seconds:
            self._chunks.popleft()

        elapsed = current_time - self._first_chunk_time
        if elapsed < self.window_seconds:
            return False, ""

        total_window_bytes = sum(c[1] for c in self._chunks)
        effective_window = max(1.0, current_time - self._chunks[0][0])
        throughput = total_window_bytes / effective_window
        if throughput < self.min_bytes_per_sec and len(self._chunks) >= 3:
            return True, f"Delay-tarpit detected: stream throughput {throughput:.1f} B/s over {effective_window:.1f}s"

        if len(self._chunks) >= 5:
            hashes = [c[2] for c in self._chunks]
            if len(set(hashes)) == 1:
                no_finding_elapsed = current_time - (self._last_finding_time or self._first_chunk_time)
                if no_finding_elapsed >= self.window_seconds:
                    return True, f"Banner loop detected: identical chunk repeating for {no_finding_elapsed:.1f}s with 0 findings"

        return False, ""


class Executor:
    """Executes tools and manages their lifecycle and output persistence."""

    def __init__(self, store: Optional[GraphStore] = None):
        self.store = store
        self._active_processes: Dict[str, asyncio.subprocess.Process] = {}
        self._last_exit_codes: Dict[str, int] = {}

    def get_exit_code(self, task_id: str) -> Optional[int]:
        """Return the last recorded process exit code for a task ID, if available."""
        return self._last_exit_codes.get(task_id)

    async def run(
        self,
        adapter: ToolAdapter,
        target: BaseFinding,
        params: Dict[str, Any],
        task_id: str,
        cwd: str,
        env: Optional[Dict[str, str]] = None,
        use_shell: bool = False,
        shell_path: Optional[str] = None,
        on_output: Optional[Callable[[str], Any]] = None,
        on_error_output: Optional[Callable[[str], Any]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> AsyncIterator[BaseFinding]:
        """Execute a tool adapter via CommandRunner protocol."""
        async for finding in self.run_tool(
            adapter=adapter,
            target=target,
            params=params,
            session_id=None,
            task_id=task_id,
            cwd=cwd,
            env=env,
            use_shell=use_shell,
            shell_path=shell_path,
            on_output=on_output,
            on_error_output=on_error_output,
            timeout_seconds=timeout_seconds,
        ):
            yield finding

    async def stop(self, task_id: str) -> None:
        """Terminate a running task via CommandRunner protocol."""
        await self.stop_task(task_id)

    async def stop_task(self, task_id: str) -> None:
        """Forcefully terminate a specific running task."""
        process = self._active_processes.pop(task_id, None)
        if process:
            try:
                if process.returncode is None:
                    process.terminate()
                    await process.wait()
                logger.info(f"Terminated process for task {task_id}")
            except Exception as e:
                logger.error(f"Error terminating process: {e}")

    async def shutdown(self) -> None:
        """Forcefully terminate all active tool processes."""
        tasks = list(self._active_processes.keys())
        for task_id in tasks:
            await self.stop_task(task_id)

    async def run_tool(
        self,
        adapter: ToolAdapter,
        target: BaseFinding,
        params: Dict[str, Any],
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        use_shell: bool = False,
        shell_path: Optional[str] = None,
        on_output: Optional[Callable[[str], Coroutine]] = None,
        on_error_output: Optional[Callable[[str], Coroutine]] = None,
        timeout_seconds: Optional[int] = None,
        log_file_path: Optional[str] = None,
    ) -> AsyncIterator[BaseFinding]:
        """
        Execute a tool adapter against a target finding and yield findings.
        """
        if not adapter.validate_install():
            raise RuntimeError(f"Tool binary for {adapter.__class__.__name__} not found on system.")

        tracking_id = task_id or session_id
        start_time = asyncio.get_event_loop().time()

        command = adapter.build_command(target, params)
        clean_env = sanitize_subprocess_env(env)

        if use_shell:
            default_shell = shell_path or shutil.which("bash") or os.environ.get("SHELL", "/bin/sh")
            raw_flags = params.get("raw_flags") if params else None
            cmd_str = raw_flags.strip() if raw_flags else shlex.join(command)
            final_cmd = [default_shell, "-c", cmd_str]
            process = await asyncio.create_subprocess_exec(
                *final_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                cwd=cwd,
                env=clean_env,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                cwd=cwd,
                env=clean_env,
            )

        if tracking_id:
            self._active_processes[tracking_id] = process

        # Internal queue to bridge stream readers and findings generator
        finding_queue: asyncio.Queue[BaseFinding] = asyncio.Queue()
        parsing_context = {"params": params}  # Shared context for the duration of this tool run
        spooler = LogSpooler(log_file_path) if (log_file_path and not on_output) else None
        tarpit_guard = StreamTarpitGuard(window_seconds=15.0)
        tarpit_flag = [False]

        async def _drain_stream(stream, callback, is_stdout=True):
            buffer = ""
            try:
                while True:
                    # 64KB read chunks for high-throughput stream draining without event loop starvation
                    chunk = await stream.read(65536)
                    if not chunk:
                        # Process any remaining text in the buffer as a final line
                        if buffer and is_stdout:
                            final_line = buffer.split("\r")[-1].strip()
                            if final_line:
                                async for finding in adapter.parse_output(
                                    final_line, target, context=parsing_context
                                ):
                                    tarpit_guard.record_finding(asyncio.get_event_loop().time())
                                    await finding_queue.put(finding)
                        break

                    # Inline tarpit anomaly detection (slow drip or infinite banner loops)
                    if is_stdout:
                        is_tarpit, tarpit_reason = tarpit_guard.check_chunk(
                            len(chunk), chunk, asyncio.get_event_loop().time()
                        )
                        if is_tarpit:
                            tarpit_flag[0] = True
                            msg = f"\n[TARPIT DETECTED] {tarpit_reason}. Aborting execution...\n"
                            logger.warning(msg.strip())
                            if spooler:
                                spooler.write(msg)
                            if callback:
                                await callback(msg)
                            elif on_output:
                                await on_output(msg)
                            if process.returncode is None:
                                process.terminate()
                                try:
                                    await asyncio.wait_for(process.wait(), timeout=2.0)
                                except Exception:
                                    process.kill()
                            break

                    raw_text = chunk.decode(errors="replace")
                    if spooler:
                        spooler.write(raw_text)

                    if callback:
                        await callback(raw_text)
                    elif on_output:
                        await on_output(raw_text)

                    # Tool parsing only on stdout
                    if is_stdout:
                        cleaned = strip_ansi(raw_text).replace("\r\n", "\n")
                        buffer += cleaned

                        # In-stream carriage return defense: if buffer has \r without \n and exceeds 4KB,
                        # collapse intermediate overwrites so memory stays strictly bounded
                        if "\r" in buffer and "\n" not in buffer and len(buffer) > 4096:
                            buffer = buffer.split("\r")[-1]

                        if "\n" in buffer:
                            lines = buffer.split("\n")
                            buffer = lines.pop()
                            for line in lines:
                                # Collapse in-place \r overwrite within the completed line
                                collapsed = line.split("\r")[-1].strip()
                                if not collapsed:
                                    continue
                                try:
                                    async for finding in adapter.parse_output(
                                        collapsed, target, context=parsing_context
                                    ):
                                        tarpit_guard.record_finding(asyncio.get_event_loop().time())
                                        await finding_queue.put(finding)
                                except Exception as parse_e:
                                    logger.error(f"Error parsing line '{collapsed}': {parse_e}")

                    # Explicitly yield control to the asyncio event loop in tight streaming loops
                    await asyncio.sleep(0.001)
            except Exception as e:
                logger.error(f"Error draining stream: {e}")

        # Start drain tasks
        stdout_task = asyncio.create_task(_drain_stream(process.stdout, on_output, is_stdout=True))
        stderr_task = asyncio.create_task(
            _drain_stream(process.stderr, on_error_output or on_output, is_stdout=False)
        )

        try:
            # Wait for process and stream tasks to finish
            # We don't use gather directly because we want to yield as findings arrive
            while not (
                stdout_task.done() and stderr_task.done() and process.returncode is not None
            ):
                # Check for execution timeout
                if (
                    timeout_seconds is not None
                    and (asyncio.get_event_loop().time() - start_time) > timeout_seconds
                ):
                    if on_output:
                        await on_output(
                            f"\n[TIMEOUT] Tool execution exceeded {timeout_seconds} seconds. Terminating process...\n"
                        )
                    if process.returncode is None:
                        process.terminate()
                    raise TimeoutError(f"Tool execution timed out after {timeout_seconds} seconds.")

                try:
                    # Wait for finding or a small timeout to check process state
                    finding = await asyncio.wait_for(finding_queue.get(), timeout=0.1)
                    yield finding
                except asyncio.TimeoutError:
                    # Just checking if process finished
                    if process.returncode is None:
                        # Check if process actually finished while we were waiting
                        # but it might still have data in pipes
                        pass

                # Check process return code
                if process.returncode is None:
                    try:
                        # Non-blocking wait
                        await asyncio.wait_for(process.wait(), timeout=0.01)
                    except asyncio.TimeoutError:
                        pass

            # Final check of the queue for any remaining findings
            while not finding_queue.empty():
                finding = finding_queue.get_nowait()
                yield finding

        except asyncio.CancelledError:
            if process.returncode is None:
                process.terminate()
            raise
        finally:
            if tracking_id:
                self._active_processes.pop(tracking_id, None)

            # Ensure readers are cleaned up
            stdout_task.cancel()
            stderr_task.cancel()

            if process.returncode is None:
                try:
                    process.terminate()
                    await process.wait()
                except Exception:
                    pass

            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            if spooler:
                spooler.close()

            if tarpit_flag[0] and self.store and hasattr(self.store, "upsert_node_belief"):
                try:
                    target_id = getattr(target, "id", None) or "unknown"
                    await self.store.upsert_node_belief(
                        node_id=target_id,
                        session_id=session_id or "default",
                        confidence=0.1,
                        is_tarpit=1,
                        indicators=["inline_stream_tarpit"],
                    )
                except Exception as store_e:
                    logger.error(f"Failed to record tarpit belief: {store_e}")

        if tracking_id and process.returncode is not None:
            self._last_exit_codes[tracking_id] = process.returncode

        if process.returncode is not None and process.returncode != 0:
            logger.error(f"Command failed with exit code {process.returncode}")
            if process.returncode == 127:
                raise RuntimeError(f"Tool not found: {command[0]}")
            non_fatal = getattr(adapter, "non_fatal_exit_codes", ())
            if process.returncode not in non_fatal:
                raise RuntimeError(
                    f"Command '{command[0]}' failed with exit code {process.returncode}"
                )
