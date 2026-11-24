"""DNSRecon tool adapter."""

import json
import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.dns import DnsRecord

_TEXT_PATTERN = re.compile(r"\[\*\]\s+([A-Z]+)\s+([^\s:]+)\s+(\S+)")


class DnsreconAdapter(ToolAdapter):
    """Adapter for DNSRecon enumeration tool."""

    name = "dnsrecon"

    def validate_install(self) -> bool:
        return self.is_binary_available("dnsrecon")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        domain = target.pik.get("domain") or target.data.get("domain")
        raw_flags = params.get("raw_flags", "")

        args = ["dnsrecon", "-j", "-"]
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        if domain and "-d" not in args:
            args.extend(["-d", domain])
        elif not domain and not raw_flags:
            raise ValueError("Target finding must specify a domain for dnsrecon.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        target_domain = target.pik.get("domain") or target.data.get("domain") or "example.com"
        clean = self.strip_ansi(raw_stdout).strip()
        if not clean:
            return

        # JSON parsing
        if clean.startswith("[") or clean.startswith("{"):
            try:
                data = json.loads(clean)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    rtype = item.get("type")
                    name = item.get("name") or target_domain
                    val = item.get("address") or item.get("target") or item.get("strings")
                    if rtype and val:
                        yield DnsRecord.create(
                            domain=name,
                            record_type=str(rtype).upper(),
                            value=str(val),
                        )
                return
            except Exception:
                pass

        # Text line parsing
        for line in clean.splitlines():
            m = _TEXT_PATTERN.search(line)
            if m:
                rtype, name, val = m.group(1), m.group(2), m.group(3)
                yield DnsRecord.create(
                    domain=name,
                    record_type=rtype.upper(),
                    value=val,
                )
