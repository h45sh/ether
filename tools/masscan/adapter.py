"""Masscan tool adapter."""

import json
import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkService

_DISCOVER_PATTERN = re.compile(
    r"Discovered open port (\d+)/(tcp|udp) on (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)


class MasscanAdapter(ToolAdapter):
    """Adapter for the masscan asynchronous port scanner."""

    name = "masscan"

    def validate_install(self) -> bool:
        return self.is_binary_available("masscan")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        target_ip = self.extract_host(target)
        if not target_ip and target.schema_type == "network.netblock":
            target_ip = target.pik.get("cidr") or target.data.get("cidr")

        raw_flags = params.get("raw_flags", "")

        args = ["masscan"]
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        if not any(f in args for f in ("-oJ", "-oG", "-oX")):
            args.extend(["-oJ", "-"])

        if not any(f.startswith("-p") for f in args):
            args.extend(["-p", "80,443,22,21,25,8080,8443"])

        if target_ip and target_ip not in args:
            args.append(target_ip)
        elif not target_ip and not raw_flags:
            raise ValueError("Target finding must specify an IP address or CIDR for masscan.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        clean_text = self.strip_ansi(raw_stdout).strip()
        if not clean_text:
            return

        # Attempt to parse as JSON block or stream
        if clean_text.startswith("[") or clean_text.startswith("{"):
            try:
                # Masscan JSON output format is [{ "ip": "...", "ports": [{"port": 80, "proto": "tcp"}] }]
                data = json.loads(clean_text)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    ip = item.get("ip")
                    for p in item.get("ports", []):
                        port = p.get("port")
                        proto = p.get("proto", "tcp")
                        if ip and port:
                            yield NetworkService.create(
                                host_ip=ip,
                                port=int(port),
                                protocol=proto,
                                service_name="unknown",
                                firewall_reason="allowed",
                            )
                return
            except Exception:
                pass

        # Parse line by line text output
        for line in clean_text.splitlines():
            m = _DISCOVER_PATTERN.search(line)
            if m:
                port, proto, ip = m.group(1), m.group(2), m.group(3)
                yield NetworkService.create(
                    host_ip=ip,
                    port=int(port),
                    protocol=proto.lower(),
                    service_name="unknown",
                    firewall_reason="allowed",
                )
