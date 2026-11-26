"""OWASP Amass tool adapter."""

import json
import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.dns import DomainInfo
from ether.schemas.network import NetworkHost

_DOMAIN_PATTERN = re.compile(r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")


class AmassAdapter(ToolAdapter):
    """Adapter for OWASP Amass attack surface mapper."""

    name = "amass"

    def validate_install(self) -> bool:
        return self.is_binary_available("amass")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        domain = (
            target.pik.get("domain")
            or target.data.get("domain")
            or self.extract_host(target)
            or "target.local"
        )
        flag_args = self.expand_flag_macros(self.normalize_flags(params), target)

        args = ["amass", "enum", "-o", "-"]
        args.extend(flag_args)

        if domain and "-d" not in args:
            args.extend(["-d", domain])

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            # JSON line
            if clean.startswith("{") and clean.endswith("}"):
                try:
                    data = json.loads(clean)
                    name = data.get("name")
                    if name:
                        yield DomainInfo.create(domain=name)
                    for addr in data.get("addresses", []):
                        ip = addr.get("ip")
                        if ip:
                            yield NetworkHost.create(ip=ip)
                    continue
                except Exception:
                    pass

            # Plain domain name text
            if _DOMAIN_PATTERN.match(clean):
                yield DomainInfo.create(domain=clean)
