"""WPScan tool adapter."""

import json
import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.vulnerability import VulnerabilityFound

_CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b")


class WpscanAdapter(ToolAdapter):
    """Adapter for WPScan WordPress vulnerability scanner."""

    name = "wpscan"

    def validate_install(self) -> bool:
        return self.is_binary_available("wpscan")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        url = self.extract_url(target)
        flag_args = self.normalize_flags(params)

        args = ["wpscan", "-f", "json", "--no-banner"]
        if flag_args:
            args.extend(flag_args)

        if url and "--url" not in args and "-u" not in args:
            args.extend(["--url", url])
        elif not url and not flag_args:
            raise ValueError("Target finding must specify a URL for wpscan.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        host_ip = (
            target.data.get("host_ip")
            or target.pik.get("host_ip")
            or target.pik.get("ip")
            or "127.0.0.1"
        )
        url = self.extract_url(target) or ""
        clean = self.strip_ansi(raw_stdout).strip()
        if not clean:
            return

        # Attempt JSON parsing
        if clean.startswith("{") or clean.startswith("["):
            try:
                data = json.loads(clean)
                # Check version vulnerabilities
                version_info = data.get("version", {})
                for v in version_info.get("vulnerabilities", []):
                    title = v.get("title", "WordPress Core Vulnerability")
                    cve = next((r for r in v.get("references", {}).get("cve", [])), "CVE-UNKNOWN")
                    yield VulnerabilityFound.create(
                        host_ip=host_ip,
                        vuln_id=cve if cve.startswith("CVE") else f"WP-{cve}",
                        title=title,
                        severity="high",
                    )

                # Check plugin vulnerabilities
                plugins = data.get("plugins", {})
                for p_name, p_data in plugins.items():
                    for v in p_data.get("vulnerabilities", []):
                        title = v.get("title", f"Vulnerable plugin: {p_name}")
                        yield VulnerabilityFound.create(
                            host_ip=host_ip,
                            vuln_id=f"WP-PLUGIN-{p_name.upper()}",
                            title=title,
                            severity="medium",
                        )
                return
            except Exception:
                pass

        # Text line fallback
        for line in clean.splitlines():
            m = _CVE_PATTERN.search(line)
            if m:
                cve_id = m.group(1)
                yield VulnerabilityFound.create(
                    host_ip=host_ip,
                    vuln_id=cve_id,
                    title=f"WPScan Finding ({cve_id})",
                    severity="medium",
                )
