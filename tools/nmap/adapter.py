"""Nmap tool adapter."""

import re
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence

from ether.common.context import ExecutionContext
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
_XML_PRODUCT_PATTERN = re.compile(r'product="([^"]+)"')
_XML_VERSION_PATTERN = re.compile(r'version="([^"]+)"')
_XML_EXTRAINFO_PATTERN = re.compile(r'extrainfo="([^"]+)"')
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


def _is_narrow_port_spec(port_spec: str) -> bool:
    """Return True if port_spec is an explicit list of <= 20 discrete ports."""
    if not port_spec or "-" in port_spec:
        return False
    parts = [p.strip() for p in port_spec.split(",") if p.strip()]
    return bool(parts) and len(parts) <= 20 and all(p.isdigit() for p in parts)


def _should_use_two_stage(flags: Sequence[str]) -> bool:
    """Return True when -sV/-A is combined with broad/default port discovery."""
    has_version = any(
        tok in ("-sV", "-A", "--version-all", "--version-light", "--version-intensity")
        or tok.startswith("--version-intensity=")
        for tok in flags
    )
    if not has_version:
        return False

    idx = 0
    while idx < len(flags):
        tok = flags[idx]
        if tok == "-p-":
            return True
        if tok == "-p" and idx + 1 < len(flags):
            return not _is_narrow_port_spec(flags[idx + 1])
        if tok.startswith("-p") and len(tok) > 2:
            return not _is_narrow_port_spec(tok[2:])
        if tok == "--top-ports" and idx + 1 < len(flags):
            try:
                return int(flags[idx + 1]) > 20
            except ValueError:
                return True
        if tok.startswith("--top-ports="):
            try:
                return int(tok.split("=", 1)[1]) > 20
            except ValueError:
                return True
        idx += 1
    return True


def _strip_version_flags(flags: Sequence[str]) -> List[str]:
    """Strip -sV/-A/version flags for Stage 1 fast port discovery."""
    out: List[str] = []
    skip_next = False
    for tok in flags:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-sV", "-A", "--version-all", "--version-light"):
            continue
        if tok == "--version-intensity":
            skip_next = True
            continue
        if tok.startswith("--version-intensity="):
            continue
        out.append(tok)
    return out


def _build_stage2_flags(flags: Sequence[str], open_ports: Sequence[int]) -> List[str]:
    """Replace broad port flags with -p <open_ports> for Stage 2 -sV enrichment."""
    out: List[str] = []
    skip_next = False
    for tok in flags:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-p", "--top-ports"):
            skip_next = True
            continue
        if tok == "-p-" or tok.startswith(("-p", "--top-ports=")):
            continue
        out.append(tok)
    port_list = ",".join(str(p) for p in sorted(set(open_ports)))
    out.extend(["-p", port_list])
    return out


def _compute_stage_timeouts(total_timeout: Optional[float]) -> tuple[float, float]:
    """Split total timeout into 35% (clamped 10s..45s) for Stage 1 and remainder for Stage 2."""
    total = float(total_timeout) if total_timeout is not None else 120.0
    if total <= 10.0:
        stage1 = max(1.0, total * 0.35)
    else:
        stage1 = min(45.0, max(10.0, total * 0.35))
    stage2 = max(1.0, total - stage1)
    return stage1, stage2


def _finding_key(finding: BaseFinding) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Return a hashable deterministic identity key for deduplicating stage findings."""
    return (
        finding.schema_type,
        tuple(sorted((str(k), str(v)) for k, v in finding.pik.items())),
    )


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

        flag_args = self.normalize_flags(params)
        args.extend(flag_args)

        # Add streaming XML flag if not explicitly overridden
        if not any(flag in args for flag in ("-oX", "-oN", "-oG", "-oA")):
            args.extend(["-oX", "-"])

        if ip and ip not in args:
            args.append(ip)
        elif not (flag_args or ip):
            raise ValueError(
                "Target finding must have an IP address, or provide one in the command flags."
            )

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        """Dual-format streaming parser for Nmap XML and plain text output with firewall reason classification."""
        context = context or {}
        if context.get("is_partial") and "<nmaprun" in raw_stdout:
            from ether.common.recovery import salvage_xml_elements

            for elem_str in salvage_xml_elements(raw_stdout, "port"):
                port_m = _XML_PORT_PATTERN.search(elem_str)
                if port_m:
                    proto = port_m.group(1) or port_m.group(4)
                    pid = port_m.group(2) or port_m.group(3)
                    state_m = _XML_STATE_PATTERN.search(elem_str)
                    state = state_m.group(1) if state_m else "open"
                    if state == "open" and pid:
                        host_ip = target.pik.get("ip") or target.data.get("ip") or "0.0.0.0"
                        yield NetworkService.create(
                            host_ip=host_ip,
                            port=int(pid),
                            protocol=proto or "tcp",
                            service_name="unknown",
                        )

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

                prod_m = _XML_PRODUCT_PATTERN.search(clean_line)
                ver_m = _XML_VERSION_PATTERN.search(clean_line)
                extra_m = _XML_EXTRAINFO_PATTERN.search(clean_line)
                banner_parts = [m.group(1) for m in (prod_m, ver_m, extra_m) if m]
                banner = " ".join(banner_parts) if banner_parts else None

                fw_reason = _classify_firewall_reason(state, reason)

                include_all = bool(
                    context.get("include_all_states")
                    or context.get("params", {}).get("include_all_states")
                )
                if not include_all and state.lower() in ("closed", "filtered", "closed|filtered"):
                    continue

                host_ip = context.get("current_host_ip") or target.pik.get("ip")
                if host_ip and pid:
                    yield NetworkService.create(
                        host_ip=host_ip,
                        port=int(pid),
                        protocol=proto or "tcp",
                        service_name=service_name,
                        firewall_reason=fw_reason,
                        banner=banner,
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
                    rest_tokens = clean_line.split(None, 4)
                    banner = rest_tokens[4].strip() if len(rest_tokens) > 4 else None
                    fw_reason = _classify_firewall_reason(state, "")

                    include_all = bool(
                        context.get("include_all_states")
                        or context.get("params", {}).get("include_all_states")
                    )
                    if not include_all and state.lower() in (
                        "closed",
                        "filtered",
                        "closed|filtered",
                    ):
                        continue

                    yield NetworkService.create(
                        host_ip=host_ip,
                        port=port,
                        protocol=protocol,
                        service_name=service,
                        firewall_reason=fw_reason,
                        banner=banner,
                    )

    async def _run_stage(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
        stage_task_id: str,
        timeout_seconds: Optional[float],
    ) -> tuple[List[BaseFinding], List[int], bool]:
        """Run one nmap subprocess stage, returning (yielded_findings, open_ports, timed_out)."""
        stdout_chunks: List[str] = []
        yielded: List[BaseFinding] = []
        open_ports: List[int] = []
        seen_ids: set[tuple[str, tuple[tuple[str, str], ...]]] = set()

        async def _on_stdout(chunk: str) -> None:
            stdout_chunks.append(chunk)
            await context.spool_line(chunk, is_error=False)

        async def _on_stderr(chunk: str) -> None:
            await context.spool_line(chunk, is_error=True)

        timed_out = False
        try:
            async for finding in context.runner.run(
                adapter=self,
                target=target,
                params=params,
                task_id=stage_task_id,
                cwd=context.cwd,
                env=context.env,
                use_shell=context.use_shell,
                shell_path=context.shell_path,
                on_output=_on_stdout,
                on_error_output=_on_stderr,
                timeout_seconds=timeout_seconds,
            ):
                seen_ids.add(_finding_key(finding))
                yielded.append(finding)
                if finding.schema_type == "network.service" and "port" in finding.pik:
                    open_ports.append(int(finding.pik["port"]))
        except TimeoutError:
            timed_out = True
            raw_xml = "".join(stdout_chunks)
            async for salvaged in self.parse_output(
                raw_xml, target, context={"is_partial": True, "params": params}
            ):
                salvaged_id = _finding_key(salvaged)
                if salvaged_id not in seen_ids:
                    seen_ids.add(salvaged_id)
                    yielded.append(salvaged)
                    if salvaged.schema_type == "network.service" and "port" in salvaged.pik:
                        open_ports.append(int(salvaged.pik["port"]))
            await context.spool_line(
                f"[TIMEOUT] Nmap stage '{stage_task_id}' timed out; salvaged {len(yielded)} findings.",
                is_error=True,
            )

        return yielded, open_ports, timed_out

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Execute nmap with adaptive two-stage discovery -> -sV enrichment and partial salvage."""
        if context.runner is None:
            raise RuntimeError(
                "Cannot execute subprocess tool 'NmapAdapter' without a CommandRunner in ExecutionContext."
            )

        flags = self.normalize_flags(params)
        if not _should_use_two_stage(flags):
            findings, _, _ = await self._run_stage(
                target=target,
                params=params,
                context=context,
                stage_task_id=context.action_id,
                timeout_seconds=context.timeout_seconds,
            )
            for finding in findings:
                yield finding
            return

        stage1_timeout, stage2_timeout = _compute_stage_timeouts(context.timeout_seconds)
        stage1_params = {**params, "flags": _strip_version_flags(flags)}
        await context.spool_line(
            f"[*] Nmap adaptive Stage 1 (port discovery, timeout={stage1_timeout:.1f}s)..."
        )
        s1_findings, open_ports, s1_timed_out = await self._run_stage(
            target=target,
            params=stage1_params,
            context=context,
            stage_task_id=f"{context.action_id}:stage1",
            timeout_seconds=stage1_timeout,
        )
        for finding in s1_findings:
            yield finding

        if s1_timed_out or not open_ports:
            return

        stage2_params = {**params, "flags": _build_stage2_flags(flags, open_ports)}
        await context.spool_line(
            f"[*] Nmap adaptive Stage 2 (-sV on {len(set(open_ports))} open ports, timeout={stage2_timeout:.1f}s)..."
        )
        s2_findings, _, _ = await self._run_stage(
            target=target,
            params=stage2_params,
            context=context,
            stage_task_id=f"{context.action_id}:stage2",
            timeout_seconds=stage2_timeout,
        )
        for finding in s2_findings:
            yield finding
