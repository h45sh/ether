"""Ghauri SQL injection tool adapter."""

import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebVulnerability

_GHAURI_INJECTION_PATTERN = re.compile(
    r"(?:parameter\s+'([^']+)'\s+is\s+vulnerable|vulnerable\s+parameter:\s*(\S+))",
    re.IGNORECASE,
)


class GhauriAdapter(ToolAdapter):
    """Adapter for Ghauri advanced SQL injection detection tool."""

    name = "ghauri"

    def validate_install(self) -> bool:
        return self.is_binary_available("ghauri")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        url = self.extract_url(target)
        raw_flags = params.get("raw_flags", "")

        args = ["ghauri", "--batch"]
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        if url and "-u" not in args and "--url" not in args:
            args.extend(["-u", url])
        elif not url and not raw_flags:
            raise ValueError("Target finding must specify a URL for ghauri.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        target_url = self.extract_url(target) or ""

        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            m = _GHAURI_INJECTION_PATTERN.search(clean)
            if m:
                param = m.group(1) or m.group(2)
                yield WebVulnerability.create(
                    url=target_url,
                    vuln_type="sql_injection",
                    severity="high",
                    title=f"SQL Injection in parameter '{param}'",
                    payload=clean,
                )
