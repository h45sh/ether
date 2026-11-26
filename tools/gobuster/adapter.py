"""Gobuster tool adapter."""

import re
from typing import Any, AsyncIterator, Dict, List

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
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
                flag_list = self.normalize_flags(params)
                if "--exclude-length" not in flag_list:
                    params["flags"] = [*flag_list, "--exclude-length", str(calib["size"])]

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
        flag_args = self.expand_flag_macros(self.normalize_flags(params), target)
        args.extend(flag_args)
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
            raw_flags = " ".join(self.normalize_flags(context.get("params")))
            url_match = self.URL_FLAG_RE.search(raw_flags)
            if url_match:
                base_url = url_match.group(1).rstrip("/")

        for line in raw_stdout.splitlines():
            clean_line = self.strip_ansi(line)
            if len(clean_line) > 4096:
                clean_line = clean_line[:4096]
            if " (Status:" not in clean_line:
                continue

            part_path, _, rest = clean_line.partition(" (Status:")
            path_tokens = part_path.strip().split()
            if not path_tokens:
                continue
            path = path_tokens[-1]
            status_str, _, _ = rest.partition(")")
            status_str = status_str.strip()
            if not status_str.isdigit():
                continue

            status_code = int(status_str)
            full_url = f"{base_url}{path}" if base_url else path

            yield WebEndpoint.create(url=full_url, method="GET", status_code=status_code)
