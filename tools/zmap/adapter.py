"""ZMap single-packet network scanner tool adapter."""

import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost, NetworkService

_IP_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class ZmapAdapter(ToolAdapter):
    """Adapter for ZMap single-packet scanner."""

    name = "zmap"

    def validate_install(self) -> bool:
        return self.is_binary_available("zmap")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        target_ip = self.extract_host(target)
        if not target_ip and target.schema_type == "network.netblock":
            target_ip = target.pik.get("cidr") or target.data.get("cidr")

        raw_flags = params.get("raw_flags", "")

        args = ["zmap", "-p", "80", "-o", "-"]
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        if target_ip and target_ip not in args:
            args.append(target_ip)
        elif not target_ip and not raw_flags:
            raise ValueError("Target finding must specify an IP address or subnet for zmap.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            m = _IP_PATTERN.match(clean)
            if m:
                ip = m.group(1)
                yield NetworkHost.create(ip=ip)
                yield NetworkService.create(
                    host_ip=ip,
                    port=80,
                    protocol="tcp",
                    service_name="unknown",
                    firewall_reason="allowed",
                )
