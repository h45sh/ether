"""Abstract base class for all tool plugins."""

import asyncio
import functools
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional


@dataclass(frozen=True)
class ToolCapabilities:
    """Declarative engine-to-tool capability and pipeline chaining contract."""

    name: str
    accepts: List[str] = field(default_factory=list)
    produces: List[str] = field(default_factory=list)
    amplifies_to: List[str] = field(default_factory=list)
    output_format: str = "text"
    supports_streaming_parse: bool = True

from ether.common import strip_ansi as _strip_ansi
from ether.common.context import ExecutionContext
from ether.schemas.base import BaseFinding


@functools.lru_cache(maxsize=128)
def is_binary_available(binary: str) -> bool:
    """Cached check for binary existence in PATH to avoid repeated filesystem stats."""
    return shutil.which(binary) is not None


def clear_binary_cache() -> None:
    """Clear cached binary lookup table for fresh filesystem validation."""
    is_binary_available.cache_clear()


class ToolAdapter(ABC):
    """Contract for tool contributors.

    Every tool in tools/ must implement this in adapter.py.
    """

    name: str = ""
    execution_tier: str = "subprocess"
    supports_streaming_parse: bool = True

    def get_structured_default_flags(self) -> List[str]:
        """Return preferred machine-readable output flags when not overridden by caller."""
        return []

    def get_capabilities(self, manifest: Optional[Any] = None) -> ToolCapabilities:
        """Return declarative input/output/chaining capabilities for pipeline amplification."""
        accepts = list(manifest.input.get("accepts", [])) if manifest else []
        produces = list(manifest.output.get("produces", [])) if manifest else []
        exec_cfg = getattr(manifest, "execution", None) if manifest else None
        out_fmt = getattr(exec_cfg, "output_format", "text") if exec_cfg else "text"
        streaming = getattr(exec_cfg, "supports_streaming_parse", self.supports_streaming_parse) if exec_cfg else self.supports_streaming_parse
        amplifies: List[str] = []
        if "network.service" in produces:
            amplifies.extend(["http_probe", "tls_probe", "nuclei"])
        elif "web.endpoint" in produces:
            amplifies.extend(["nuclei", "ffuf", "imds_probe"])
        elif "domain.info" in produces:
            amplifies.extend(["dns_lookup", "subfinder", "http_probe"])
        return ToolCapabilities(
            name=self.name,
            accepts=accepts,
            produces=produces,
            amplifies_to=amplifies,
            output_format=out_fmt,
            supports_streaming_parse=streaming,
        )

    @staticmethod
    def is_binary_available(binary: str) -> bool:
        """Cached check for whether a tool binary exists in PATH."""
        return is_binary_available(binary)

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Unified execution seam across Tier A coroutines and Tier B subprocesses.

        By default, runs Tier B command-line binary via context.runner.
        Tier A native coroutine adapters override this method.
        """
        if context.runner is None:
            raise RuntimeError(
                f"Cannot execute subprocess tool '{self.name or self.__class__.__name__}' without a CommandRunner in ExecutionContext."
            )

        from collections import deque

        max_history_bytes = 2 * 1024 * 1024
        stdout_lines: deque[str] = deque()
        history_bytes = 0

        async def _on_stdout(chunk: str) -> None:
            nonlocal history_bytes
            chunk_bytes = len(chunk.encode("utf-8", errors="replace"))
            stdout_lines.append(chunk)
            history_bytes += chunk_bytes
            while stdout_lines and history_bytes > max_history_bytes:
                evicted = stdout_lines.popleft()
                history_bytes -= len(evicted.encode("utf-8", errors="replace"))
            await context.spool_line(chunk, is_error=False)

        async def _on_stderr(chunk: str) -> None:
            await context.spool_line(chunk, is_error=True)

        try:
            async for finding in context.runner.run(
                adapter=self,
                target=target,
                params=params,
                task_id=context.action_id,
                cwd=context.cwd,
                env=context.env,
                use_shell=context.use_shell,
                shell_path=context.shell_path,
                on_output=_on_stdout,
                on_error_output=_on_stderr,
                timeout_seconds=context.timeout_seconds,
            ):
                yield finding
        except (TimeoutError, asyncio.TimeoutError):
            raw_history = "".join(stdout_lines).strip()
            if raw_history:
                try:
                    async for finding in self.parse_output(
                        raw_history, target, context={"params": params, "is_partial": True}
                    ):
                        yield finding
                except Exception:
                    pass
            raise

    @abstractmethod
    def validate_install(self) -> bool:
        """Check if the tool binary is available on the system."""
        pass

    @abstractmethod
    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Build the command line arguments for the tool.

        Args:
            target: The finding being scanned (e.g. a network.host)
            params: User-provided flags or options from the caller (CLI, MCP, or SDK)
        """
        pass

    @abstractmethod
    def parse_output(
        self,
        raw_stdout: str,
        target: BaseFinding,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[BaseFinding]:
        """Parse tool output and yield standardized findings.

        Args:
            raw_stdout: The raw output string from the tool
            target: The original target finding (for context/parenting)
            context: Optional dictionary for tracking state across lines (e.g. current host)
        """
        pass

    @staticmethod
    def strip_ansi(text: str) -> str:
        """Strip ANSI color and cursor control sequences from terminal output."""
        return _strip_ansi(text)

    def extract_url(self, target: Optional[BaseFinding]) -> Optional[str]:
        """Resolve a full HTTP/HTTPS URL from a target finding."""
        if not target:
            return None
        st = getattr(target, "schema_type", "")
        pik = getattr(target, "pik", {}) or {}
        data = getattr(target, "data", {}) or {}

        if st in ("web.endpoint", "web.resource", "web.vulnerability"):
            return pik.get("url") or data.get("url")
        if st == "network.service":
            port = pik.get("port")
            ip = pik.get("host_ip") or data.get("host_ip") or pik.get("ip")
            if ip and port:
                scheme = "https" if int(port) in (443, 8443) else "http"
                return f"{scheme}://{ip}:{port}"
        if st == "network.host":
            ip = pik.get("ip") or pik.get("host_ip") or data.get("ip")
            return f"http://{ip}" if ip else None
        if st in ("domain.info", "dns.record"):
            domain = pik.get("domain") or data.get("domain") or data.get("value")
            return f"http://{domain}" if domain else None
        return None

    def extract_host(self, target: Optional[BaseFinding]) -> Optional[str]:
        """Resolve target IP or hostname from a finding."""
        if not target:
            return None
        st = getattr(target, "schema_type", "")
        pik = getattr(target, "pik", {}) or {}
        data = getattr(target, "data", {}) or {}

        if st == "network.host":
            return pik.get("ip") or pik.get("host_ip") or data.get("ip")
        if st == "network.service":
            return pik.get("host_ip") or data.get("host_ip") or pik.get("ip")
        if st in ("domain.info", "dns.record"):
            return pik.get("domain") or data.get("domain") or data.get("value")
        if st.startswith("web."):
            url = pik.get("url") or data.get("url")
            if url:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                return parsed.hostname or url
        return pik.get("ip") or pik.get("host_ip") or pik.get("domain")

    def extract_domain(self, target: Optional[BaseFinding]) -> Optional[str]:
        """Resolve target domain identifier from a finding."""
        if not target:
            return None
        st = getattr(target, "schema_type", "")
        pik = getattr(target, "pik", {}) or {}
        data = getattr(target, "data", {}) or {}

        if st in ("domain.info", "dns.record"):
            return pik.get("domain") or data.get("domain") or data.get("value")
        if st.startswith("web."):
            url = pik.get("url") or data.get("url")
            if url:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                return parsed.hostname or url
        return pik.get("domain")

    def extract_port(self, target: Optional[BaseFinding]) -> Optional[int]:
        """Resolve target port from a finding."""
        if not target:
            return None
        pik = getattr(target, "pik", {}) or {}
        data = getattr(target, "data", {}) or {}
        port = pik.get("port") or data.get("port")
        if port is not None:
            try:
                return int(port)
            except (ValueError, TypeError):
                pass
        return None

    def sanitize_output(self, raw_stdout: str) -> str:
        """Optional tool-specific output sanitization before LLM prompting.

        Strip tool-specific ASCII banners, progress bars, or noisy separator lines.
        Default implementation returns raw_stdout untouched.
        """
        return raw_stdout

    def parse_json_lines(self, raw_stdout: str) -> List[Dict[str, Any]]:
        """Resiliently parse newline-delimited JSON stream, skipping comments and partial chunks."""
        import json

        results = []
        clean = self.strip_ansi(raw_stdout)
        for line in clean.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            try:
                results.append(json.loads(line_str))
            except (json.JSONDecodeError, ValueError):
                continue
        return results

    def parse_regex_lines(self, raw_stdout: str, pattern: Any) -> List[Any]:
        """Match regular expression line-by-line across stripped terminal output."""
        import re

        clean = self.strip_ansi(raw_stdout)
        regex = re.compile(pattern) if isinstance(pattern, str) else pattern
        matches = []
        for line in clean.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            m = regex.search(line_str)
            if m:
                matches.append(m)
        return matches

    def extract_cves(self, text: str) -> List[str]:
        """Extract all standardized CVE identifiers (e.g. CVE-2021-44228) from text."""
        import re

        return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))
