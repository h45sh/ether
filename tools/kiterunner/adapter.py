"""Kiterunner API discovery tool adapter."""

import json
import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebEndpoint

_TEXT_PATTERN = re.compile(r"\[(\d{3})\]\s+\[[^\]]*\]\s+(\S+)")


class KiterunnerAdapter(ToolAdapter):
    """Adapter for Kiterunner (kr) API route discovery."""

    name = "kiterunner"

    def validate_install(self) -> bool:
        return self.is_binary_available("kr") or self.is_binary_available("kiterunner")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        url = self.extract_url(target)
        flag_args = self.normalize_flags(params)

        binary = "kr" if self.is_binary_available("kr") else "kiterunner"
        args = [binary, "scan"]
        if flag_args:
            args.extend(flag_args)

        if url and url not in args:
            args.append(url)
        elif not url and not flag_args:
            raise ValueError("Target finding must specify a URL for kiterunner.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            # JSON line parsing
            if clean.startswith("{") and clean.endswith("}"):
                try:
                    data = json.loads(clean)
                    url = data.get("url") or data.get("target") or data.get("path")
                    status = data.get("status") or data.get("status_code")
                    if url:
                        yield WebEndpoint.create(
                            url=url,
                            status_code=int(status) if status else None,
                        )
                    continue
                except Exception:
                    pass

            # Text format: [200] [  123B] http://target/api/v1/users
            m = _TEXT_PATTERN.search(clean)
            if m:
                status, url = m.group(1), m.group(2)
                yield WebEndpoint.create(url=url, status_code=int(status))
