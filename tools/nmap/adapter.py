"""Nmap tool adapter."""

import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost, NetworkService

_REPORT_PATTERN = re.compile(r"Nmap scan report for (?:[^\s(]+\s+)?\(?([^\s)]+)\)?")
_PORT_PATTERN = re.compile(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)")
_IP_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# XML streaming patterns
_XML_ADDR_PATTERN = re.compile(r'<address\s+[^>]*addr="([^"]+)"')
_XML_PORT_PATTERN = re.compile(
    r'<port\s+[^>]*protocol="([^"]+)"\s+[^>]*portid="([^"]+)"|<port\s+[^>]*portid="([^"]+)"\s+[^>]*protocol="([^"]+)"'
)
_XML_STATE_PATTERN = re.compile(r'<state\s+[^>]*state="([^"]+)"(?:\s+[^>]*reason="([^"]+)")?')
_XML_SERVICE_PATTERN = re.compile(r'<service\s+[^>]*name="([^"]+)"')
_XML_EXTRAREASONS_PATTERN = re.compile(r'<extrareasons\s+[^>]*reason="([^"]+)"')


def _classify_firewall_reason(state: str, reason: str = "") -> str:
    r = (reason or "").lower()
    s = (state or "").lower()
    if r in ("no-response", "host-unreach", "net-unreach", "proto-unreach") or (
        s == "filtered" and not r
    ):
        return "stateful_drop"
    if r in ("admin-prohibited", "comm-admin-prohibited"):
        return "stateless_filter"
    if r in ("reset", "conn-refused"):
        return "host_reject"
    if s == "open" or r == "syn-ack":
        return "allowed"
    return r or s


class NmapAdapter(ToolAdapter):
    """Adapter for the nmap port scanner."""

    def validate_install(self) -> bool:
        return self.is_binary_available("nmap")

    def sanitize_output(self, raw_stdout: str) -> str:
        """Strip nmap banner and timing statistics to conserve LLM context tokens."""
        lines = []
        for line in raw_stdout.splitlines():
            s = line.strip()
            if (
                s.startswith("Starting Nmap")
                or s.startswith("Nmap done:")
                or "host up (" in s.lower()
            ):
                continue
            lines.append(line)
        return "\n".join(lines)

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        # target is expected to be a network.host, but might be dummy in manual mode
        ip = self.extract_host(target)

        args = ["nmap", "--noninteractive"]

        # Handle manual raw flags from UI
        raw_flags = params.get("raw_flags", "")
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        # Add streaming XML flag if not explicitly overridden
        if not any(flag in args for flag in ("-oX", "-oN", "-oG", "-oA")):
            args.extend(["-oX", "-"])

        if ip and ip not in args:
            args.append(ip)
        elif not raw_flags:
            raise ValueError(
                "Target finding must have an IP address, or provide one in the command flags."
            )

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        """Dual-format streaming parser for Nmap XML and plain text output with firewall reason classification."""
        context = context or {}

        for line in raw_stdout.splitlines():
            clean_line = self.strip_ansi(line).strip()
            if not clean_line:
                continue

            # 1. XML Host Discovery (<address addr="10.0.0.1" addrtype="ipv4"/>)
            addr_match = _XML_ADDR_PATTERN.search(clean_line)
            if addr_match:
                host_ip = addr_match.group(1)
                context["current_host_ip"] = host_ip
                yield NetworkHost.create(ip=host_ip)
                continue

            # 2. XML Extra Reasons (<extrareasons reason="no-response" count="998"/>)
            extra_match = _XML_EXTRAREASONS_PATTERN.search(clean_line)
            if extra_match:
                context["last_extra_reason"] = extra_match.group(1)

            # 3. XML Port Discovery (<port protocol="tcp" portid="80">...<state state="open" reason="syn-ack"/>...)
            port_xml_match = _XML_PORT_PATTERN.search(clean_line)
            if port_xml_match:
                proto = port_xml_match.group(1) or port_xml_match.group(4)
                pid = port_xml_match.group(2) or port_xml_match.group(3)

                state_match = _XML_STATE_PATTERN.search(clean_line)
                state = state_match.group(1) if state_match else "open"
                reason = (
                    (state_match.group(2) if state_match else None)
                    or context.get("last_extra_reason")
                    or ""
                )

                service_match = _XML_SERVICE_PATTERN.search(clean_line)
                service_name = service_match.group(1) if service_match else "unknown"

                fw_reason = _classify_firewall_reason(state, reason)
                host_ip = context.get("current_host_ip") or target.pik.get("ip")
                if host_ip and pid:
                    yield NetworkService.create(
                        host_ip=host_ip,
                        port=int(pid),
                        protocol=proto or "tcp",
                        service_name=service_name,
                        firewall_reason=fw_reason,
                    )
                continue

            # 4. Fallback: Plain Text Host Discovery ("Nmap scan report for 10.0.0.1")
            host_match = _REPORT_PATTERN.search(clean_line)
            if host_match:
                host_ip = host_match.group(1)
                context["current_host_ip"] = host_ip
                yield NetworkHost.create(ip=host_ip)
                continue

            # 5. Fallback: Plain Text Port Discovery ("80/tcp open http" or "443/tcp filtered https")
            port_match = _PORT_PATTERN.search(clean_line)
            if port_match:
                host_ip = context.get("current_host_ip") or target.pik.get("ip")
                if not host_ip:
                    raw_flags = context.get("params", {}).get("raw_flags", "")
                    ip_match = _IP_PATTERN.search(raw_flags)
                    if ip_match:
                        host_ip = ip_match.group(1)
                        context["current_host_ip"] = host_ip

                if host_ip:
                    port = int(port_match.group(1))
                    protocol = port_match.group(2)
                    state = port_match.group(3)
                    service = port_match.group(4)
                    fw_reason = _classify_firewall_reason(state, "")

                    yield NetworkService.create(
                        host_ip=host_ip,
                        port=port,
                        protocol=protocol,
                        service_name=service,
                        firewall_reason=fw_reason,
                    )
