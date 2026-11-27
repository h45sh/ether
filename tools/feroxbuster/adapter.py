"""Feroxbuster tool adapter."""

import json
import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebEndpoint

_TEXT_PATTERN = re.compile(r"^(\d{3})\s+[A-Z]+\s+\S+\s+\S+\s+\S+\s+(https?://\S+)")


class FeroxbusterAdapter(ToolAdapter):
    """Adapter for feroxbuster fast recursive crawler."""

    name = "feroxbuster"

    def validate_install(self) -> bool:
        return self.is_binary_available("feroxbuster")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        url = self.extract_url(target)
        flag_args = self.normalize_flags(params)

        args = ["feroxbuster", "--json", "--silent"]
        if flag_args:
            args.extend(flag_args)

        if url and "-u" not in args and "--url" not in args:
            args.extend(["-u", url])
        elif not url and not flag_args:
            raise ValueError("Target finding must specify a URL for feroxbuster.")

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
                    url = data.get("url") or data.get("original_url")
                    status = data.get("status")
                    if url:
                        yield WebEndpoint.create(
                            url=url,
                            status_code=int(status) if status else None,
                        )
                    continue
                except Exception:
                    pass

            # Text line parsing
            m = _TEXT_PATTERN.match(clean)
            if m:
                status, url = m.group(1), m.group(2)
                yield WebEndpoint.create(url=url, status_code=int(status))
