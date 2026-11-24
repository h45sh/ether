"""CVE search offline tool adapter."""

import json
import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.vulnerability import VulnerabilityFound

_CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b")


class CveSearchAdapter(ToolAdapter):
    """Adapter for cve_search vulnerability query utility."""

    name = "cve_search"

    def validate_install(self) -> bool:
        return self.is_binary_available("cve_search")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        raw_flags = params.get("raw_flags", "")
        svc = target.data.get("service_name") or target.data.get("product") or "unknown"
        ver = target.data.get("version") or ""

        args = ["cve_search", "--json"]
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        query = f"{svc} {ver}".strip()
        if query and query not in args:
            args.append(query)

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        host_ip = (
            target.pik.get("host_ip")
            or target.data.get("host_ip")
            or target.pik.get("ip")
            or "127.0.0.1"
        )
        clean = self.strip_ansi(raw_stdout).strip()
        if not clean:
            return

        # JSON parsing
        if clean.startswith("[") or clean.startswith("{"):
            try:
                data = json.loads(clean)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    cve_id = item.get("id") or item.get("cve_id")
                    title = item.get("summary") or item.get("title") or "Known Vulnerability"
                    cvss = float(item.get("cvss") or 5.0)
                    severity = "critical" if cvss >= 9.0 else ("high" if cvss >= 7.0 else "medium")
                    if cve_id:
                        yield VulnerabilityFound.create(
                            host_ip=host_ip,
                            vuln_id=cve_id,
                            title=title,
                            severity=severity,
                        )
                return
            except Exception:
                pass

        # Text parsing
        for line in clean.splitlines():
            m = _CVE_PATTERN.search(line)
            if m:
                cve_id = m.group(1)
                yield VulnerabilityFound.create(
                    host_ip=host_ip,
                    vuln_id=cve_id,
                    title=f"Discovered {cve_id}",
                    severity="medium",
                )
