"""Katana headless web crawler tool adapter."""

import json
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebEndpoint


class KatanaAdapter(ToolAdapter):
    """Adapter for Katana next-gen crawler."""

    name = "katana"

    def validate_install(self) -> bool:
        return self.is_binary_available("katana")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        url = self.extract_url(target)
        raw_flags = params.get("raw_flags", "")

        args = ["katana", "-jsonl", "-silent"]
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        if url and "-u" not in args:
            args.extend(["-u", url])
        elif not url and not raw_flags:
            raise ValueError("Target finding must specify a URL for katana.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            # Check JSONL format
            if clean.startswith("{") and clean.endswith("}"):
                try:
                    data = json.loads(clean)
                    # Katana emits {"request":{"endpoint":"http://..."}, ...}
                    endpoint = (
                        data.get("request", {}).get("endpoint")
                        or data.get("endpoint")
                        or data.get("url")
                    )
                    if endpoint:
                        yield WebEndpoint.create(url=endpoint)
                    continue
                except Exception:
                    pass

            # Fallback plain URL
            if clean.startswith("http://") or clean.startswith("https://"):
                yield WebEndpoint.create(url=clean)
