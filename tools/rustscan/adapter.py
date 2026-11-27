"""Rustscan tool adapter."""

import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkService

_RUSTSCAN_PATTERN = re.compile(
    r"(?:Open|\[\+\])\s*(?:http://|https://)?([^\s:]+):(\d+)",
    re.IGNORECASE,
)


class RustscanAdapter(ToolAdapter):
    """Adapter for RustScan fast port scanner."""

    name = "rustscan"

    def validate_install(self) -> bool:
        return self.is_binary_available("rustscan")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target)
        flag_args = self.normalize_flags(params)

        args = ["rustscan", "-a"]
        if host:
            args.append(host)

        if flag_args:
            args.extend(flag_args)

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        target_host = self.extract_host(target) or "127.0.0.1"

        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            m = _RUSTSCAN_PATTERN.search(clean)
            if m:
                host, port = m.group(1), m.group(2)
                yield NetworkService.create(
                    host_ip=host if host != "localhost" else target_host,
                    port=int(port),
                    protocol="tcp",
                    service_name="unknown",
                    firewall_reason="allowed",
                )
