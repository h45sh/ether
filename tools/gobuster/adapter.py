"""Gobuster tool adapter."""

import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.registry.assets import resolve_wordlist, substitute_wordlist_macros
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebEndpoint
from tools.ffuf.adapter import calibrate_fuzzer_baseline


class GobusterAdapter(ToolAdapter):
    """Adapter for the gobuster directory brute-forcing tool."""

    URL_FLAG_RE = re.compile(r"-u\s+([^\s]+)")
    STATUS_PATTERN = re.compile(r"(\S+)\s+\(Status:\s+(\d+)\)")

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Execute gobuster scan with pre-flight response geometry baseline calibration."""
        url = self.extract_url(target)
        if url and not params.get("skip_calibration"):
            is_unrestricted = "unrestricted" in str(getattr(context, "policy", "safe")).lower()
            calib = await calibrate_fuzzer_baseline(url, policy_is_unrestricted=is_unrestricted)
            if calib and calib.get("size") is not None:
                params = dict(params)
                raw_flags = params.get("raw_flags", "")
                if "--exclude-length" not in raw_flags:
                    params["raw_flags"] = f"{raw_flags} --exclude-length {calib['size']}".strip()

        async for finding in super().execute_action(target, params, context):
            yield finding

    def validate_install(self) -> bool:
        return self.is_binary_available("gobuster")

    def sanitize_output(self, raw_stdout: str) -> str:
        """Strip Gobuster ASCII banners, progress lines, and separator lines."""
        lines = []
        for line in raw_stdout.splitlines():
            s = line.strip()
            if (
                s.startswith("==")
                or s.startswith("by OJ Reeves")
                or s.startswith("Gobuster v")
                or "[+] " in s
                or s == "Finished"
            ):
                continue
            lines.append(line)
        return "\n".join(lines)

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        args = ["gobuster"]

        raw_flags = params.get("raw_flags", "")
        if raw_flags:
            url = self.extract_url(target) or ""
            # Substitute centralized wordlist macros
            raw_flags, _ = substitute_wordlist_macros(raw_flags)
            if "{wordlist}" in raw_flags:
                default_wl = resolve_wordlist("common_dirs")
                raw_flags = raw_flags.replace("{wordlist}", str(default_wl))

            tokens = shlex.split(raw_flags)
            resolved_tokens = []
            for token in tokens:
                if "{url}" in token:
                    token = token.replace("{url}", url)
                resolved_tokens.append(token)

            args.extend(resolved_tokens)

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        """Regex parser for gobuster output.

        Example line: /admin (Status: 200) [Size: 1234]
        """
        context = context or {}

        # Base URL to construct full URLs
        base_url = (self.extract_url(target) or "").rstrip("/")

        # Try to extract base url from command params if not available
        if not base_url:
            raw_flags = context.get("params", {}).get("raw_flags", "")
            url_match = self.URL_FLAG_RE.search(raw_flags)
            if url_match:
                base_url = url_match.group(1).rstrip("/")

        for line in raw_stdout.splitlines():
            clean_line = self.strip_ansi(line)

            match = self.STATUS_PATTERN.search(clean_line)
            if match:
                path = match.group(1)
                status_code = int(match.group(2))

                full_url = f"{base_url}{path}" if base_url else path

                yield WebEndpoint.create(url=full_url, method="GET", status_code=status_code)
