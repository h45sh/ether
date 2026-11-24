"""SSLyze tool adapter for deep SSL/TLS audits."""

import json
import shlex
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import TLSCertificate
from ether.schemas.vulnerability import AuditMisconfig


class SslyzeAdapter(ToolAdapter):
    """Adapter for the SSLyze scanner."""

    name = "sslyze"

    def validate_install(self) -> bool:
        return self.is_binary_available("sslyze")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target) or "127.0.0.1"
        port = self.extract_port(target) or 443
        args = ["sslyze", f"{host}:{port}", "--json_out=-"]
        raw_flags = params.get("raw_flags", "")
        if raw_flags:
            args.extend(shlex.split(raw_flags))
        return args

    async def parse_output(
        self,
        raw_stdout: str,
        target: BaseFinding,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[BaseFinding]:
        text = raw_stdout.strip()
        if not text:
            return

        host = self.extract_host(target) or "127.0.0.1"
        port = self.extract_port(target) or 443

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    data = json.loads(text[start : end + 1])
                except Exception:
                    return
            else:
                return

        for server_scan in data.get("server_scan_results", []):
            scan_commands = server_scan.get("scan_commands_results", {})
            cert_result = scan_commands.get("certificate_info", {}).get("result", {})
            deployments = cert_result.get("certificate_deployments", [])
            for dep in deployments:
                cert = dep.get("received_certificate_chain", [{}])[0]
                fp = cert.get("fingerprint_sha256", "").replace(":", "").lower()
                if fp:
                    yield TLSCertificate.create(
                        fingerprint=fp,
                        host_ip=host,
                        port=port,
                        subject=cert.get("subject", {}).get("rfc4514_string"),
                        issuer=cert.get("issuer", {}).get("rfc4514_string"),
                    )

            hb_result = scan_commands.get("heartbleed", {}).get("result", {})
            if hb_result.get("is_vulnerable_to_heartbleed"):
                yield AuditMisconfig.create(
                    target=f"{host}:{port}",
                    check_id="ssl-heartbleed-vulnerability",
                    title="Target is Vulnerable to OpenSSL Heartbleed (CVE-2014-0160)",
                    severity="critical",
                    host_ip=host,
                )

            robot_result = scan_commands.get("robot", {}).get("result", {})
            if robot_result.get("robot_result_enum") not in ("NOT_VULNERABLE", None):
                yield AuditMisconfig.create(
                    target=f"{host}:{port}",
                    check_id="ssl-robot-vulnerability",
                    title=f"Target is Vulnerable to ROBOT Bleichenbacher Attack ({robot_result.get('robot_result_enum')})",
                    severity="high",
                    host_ip=host,
                )
