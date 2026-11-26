"""Naabu port scanner tool adapter."""

import json
import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkService

_LINE_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$")


class NaabuAdapter(ToolAdapter):
    """Adapter for the naabu fast port scanner."""

    name = "naabu"

    def validate_install(self) -> bool:
        return self.is_binary_available("naabu")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target)
        flag_args = self.normalize_flags(params)

        args = ["naabu", "-json"]
        if flag_args:
            args.extend(flag_args)

        if host and "-host" not in args:
            args.extend(["-host", host])
        elif not host and not flag_args:
            raise ValueError("Target finding must specify an IP address or hostname for naabu.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        context = context or {}
        if context.get("is_partial"):
            from ether.common.recovery import salvage_ndjson_lines

            for data in salvage_ndjson_lines(raw_stdout):
                ip = data.get("ip") or data.get("host")
                port = data.get("port")
                if ip and port:
                    yield NetworkService.create(
                        host_ip=str(ip),
                        port=int(port),
                        protocol="tcp",
                        service_name="unknown",
                        firewall_reason="allowed",
                    )

        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            # Try JSON line
            if clean.startswith("{") and clean.endswith("}"):
                try:
                    data = json.loads(clean)
                    ip = data.get("ip") or data.get("host")
                    port = data.get("port")
                    if ip and port:
                        yield NetworkService.create(
                            host_ip=str(ip),
                            port=int(port),
                            protocol="tcp",
                            service_name="unknown",
                            firewall_reason="allowed",
                        )
                    continue
                except Exception:
                    pass

            # Try text line (10.0.0.1:80)
            m = _LINE_PATTERN.match(clean)
            if m:
                ip, port = m.group(1), m.group(2)
                yield NetworkService.create(
                    host_ip=ip,
                    port=int(port),
                    protocol="tcp",
                    service_name="unknown",
                    firewall_reason="allowed",
                )
