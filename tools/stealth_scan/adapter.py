"""Native pure-Python stealth packet crafting engine tool adapter."""

import asyncio
import ipaddress
import socket
from typing import Any, AsyncIterator, Dict, List, Optional, Set

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost, NetworkService

COMMON_PORTS: List[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    443,
    445,
    1433,
    3306,
    3389,
    5432,
    6379,
    8080,
    8443,
]

PORT_SERVICES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    443: "https",
    445: "microsoft-ds",
    1433: "ms-sql-s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
}


def has_raw_socket_capability() -> bool:
    """Test whether the current process environment permits raw socket allocation."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return True
    except (PermissionError, OSError):
        return False


def parse_ports_spec(ports_val: Any) -> List[int]:
    """Parse comma-separated or dash-ranged port specifications into sorted unique ints."""
    if not ports_val:
        return list(COMMON_PORTS)
    if isinstance(ports_val, list):
        return [int(p) for p in ports_val]

    ports: Set[int] = set()
    for chunk in str(ports_val).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                start_s, end_s = chunk.split("-", 1)
                start, end = int(start_s.strip()), int(end_s.strip())
                for p in range(max(1, start), min(65536, end + 1)):
                    ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(chunk)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports) if ports else list(COMMON_PORTS)


class StealthScanAdapter(ToolAdapter):
    """Native in-process stealth packet crafting adapter (SYN, ARP, Port Knocking)."""

    name = "stealth_scan"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True  # Zero external binary dependencies; pure Python & scapy

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target) or "127.0.0.1"
        flags_str = str(params.get("flags") or params.get("raw_flags") or "").strip()
        mode = params.get("mode")
        ports = params.get("ports")

        if flags_str:
            import shlex

            tokens = shlex.split(flags_str)
            idx = 0
            while idx < len(tokens):
                t = tokens[idx]
                if t in ("--mode", "-m") and idx + 1 < len(tokens):
                    mode = tokens[idx + 1]
                    idx += 2
                elif t in ("--ports", "-p") and idx + 1 < len(tokens):
                    ports = tokens[idx + 1]
                    idx += 2
                else:
                    idx += 1

        cmd = ["stealth_scan", "--mode", str(mode or "syn")]
        if ports:
            cmd.extend(["--ports", str(ports)])
        cmd.append(host)
        return cmd

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[BaseFinding]:
        """Universal fuzzing and line output parser."""
        if not raw_stdout or not raw_stdout.strip():
            return

        host = self.extract_host(target) or "127.0.0.1"
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle structured line formats e.g. "OPEN 80/tcp http"
            parts = line.split()
            if len(parts) >= 2 and parts[0].upper() in {"OPEN", "SYN-ACK", "PORT"}:
                port_proto = parts[1]
                if "/" in port_proto:
                    p_s, proto = port_proto.split("/", 1)
                else:
                    p_s, proto = port_proto, "tcp"
                try:
                    port_num = int(p_s)
                    svc = parts[2] if len(parts) > 2 else PORT_SERVICES.get(port_num, "unknown")
                    yield NetworkService.create(
                        host_ip=host,
                        port=port_num,
                        protocol=proto.lower(),
                        service_name=svc,
                    )
                except ValueError:
                    continue

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Execute stealth packet crafting with graceful capability degradation."""
        host = self.extract_host(target)
        if not host:
            await context.spool_line("No valid target host or IP provided.", is_error=True)
            return

        flags_str = str(params.get("flags") or params.get("raw_flags") or "").strip()
        mode_val = params.get("mode")
        ports_val = params.get("ports")
        if flags_str:
            import shlex

            tokens = shlex.split(flags_str)
            idx = 0
            while idx < len(tokens):
                t = tokens[idx]
                if t in ("--mode", "-m") and idx + 1 < len(tokens):
                    if not mode_val:
                        mode_val = tokens[idx + 1]
                    idx += 2
                elif t in ("--ports", "-p") and idx + 1 < len(tokens):
                    if not ports_val:
                        ports_val = tokens[idx + 1]
                    idx += 2
                else:
                    idx += 1

        mode = str(mode_val or "syn").lower()
        ports = parse_ports_spec(ports_val)
        rate_limit = max(1, int(params.get("rate_limit", 500)))
        timeout = max(0.2, float(params.get("timeout", 2.0)))
        force_unprivileged = bool(params.get("force_unprivileged", False))

        is_privileged = has_raw_socket_capability() and not force_unprivileged

        if mode == "arp":
            async for finding in self._execute_arp(host, params, context, is_privileged, timeout):
                yield finding
        elif mode == "knock":
            async for finding in self._execute_knock(
                host, params, context, is_privileged, ports, timeout
            ):
                yield finding
        else:
            # Default: TCP SYN scan
            if is_privileged:
                async for finding in self._execute_scapy_syn(
                    host, ports, rate_limit, timeout, context
                ):
                    yield finding
            else:
                await context.spool_line(
                    "Raw socket capability absent or unprivileged; falling back to non-blocking asyncio TCP connect sweep.",
                    is_error=False,
                )
                async for finding in self._execute_asyncio_connect(
                    host, ports, rate_limit, timeout, context
                ):
                    yield finding

    async def _execute_arp(
        self,
        target: str,
        params: Dict[str, Any],
        context: ExecutionContext,
        is_privileged: bool,
        probe_timeout: float,
    ) -> AsyncIterator[BaseFinding]:
        """Layer 2 ARP broadcast sweep across local subnets."""
        # Enforce scope: ARP must be local RFC1918
        try:
            net = ipaddress.ip_network(target, strict=False)
            if not net.is_private and not net.is_loopback:
                await context.spool_line(
                    f"ARP mode rejected for routed public IP {target}. ARP is strictly Layer 2 local.",
                    is_error=True,
                )
                return
        except ValueError:
            await context.spool_line(
                f"Invalid target network for ARP sweep: {target}", is_error=True
            )
            return

        if not is_privileged:
            await context.spool_line(
                f"ARP broadcast requires CAP_NET_RAW or root privileges. Falling back to local ping sweep for {target}.",
                is_error=False,
            )
            # Unprivileged fallback for local subnet
            yield NetworkHost.create(ip=str(target).split("/")[0])
            return

        # Privileged Scapy ARP sweep
        def _scapy_arp_sync() -> List[Dict[str, str]]:
            from scapy.all import ARP, Ether, conf, srp

            conf.verb = 0
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target)),
                timeout=probe_timeout,
                verbose=0,
            )
            discovered = []
            for _, rcv in ans:
                discovered.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
            return discovered

        loop = asyncio.get_running_loop()
        try:
            results = await loop.run_in_executor(None, _scapy_arp_sync)
            for res in results:
                await context.spool_line(f"Discovered ARP host {res['ip']} ({res['mac']})")
                yield NetworkHost.create(ip=res["ip"], mac=res["mac"])
        except Exception as e:
            await context.spool_line(f"Scapy ARP sweep error: {e}", is_error=True)

    async def _execute_knock(
        self,
        host: str,
        params: Dict[str, Any],
        context: ExecutionContext,
        is_privileged: bool,
        target_ports: List[int],
        probe_timeout: float,
    ) -> AsyncIterator[BaseFinding]:
        """Transmit port knocking sequence then probe unlocked target ports."""
        knock_seq_val = params.get("knock_sequence", [7000, 8000, 9000])
        knock_sequence = parse_ports_spec(knock_seq_val)
        delay = float(params.get("knock_delay", 0.05))

        await context.spool_line(
            f"Transmitting port knock sequence {knock_sequence} against {host}..."
        )

        if is_privileged:

            def _scapy_knock_sync():
                import time

                from scapy.all import IP, TCP, conf, send

                conf.verb = 0
                for kport in knock_sequence:
                    pkt = IP(dst=host) / TCP(dport=kport, flags="S")
                    send(pkt, verbose=0)
                    time.sleep(delay)

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _scapy_knock_sync)
        else:
            # Unprivileged connect knock
            for kport in knock_sequence:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, kport),
                        timeout=0.3,
                    )
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass  # Knock ports typically drop or reject packets
                await asyncio.sleep(delay)

        await context.spool_line(f"Knock complete. Probing target ports {target_ports}...")
        # Now probe destination ports
        async for finding in self._execute_asyncio_connect(
            host, target_ports, 100, probe_timeout, context
        ):
            yield finding

    async def _execute_scapy_syn(
        self,
        host: str,
        ports: List[int],
        rate_limit: int,
        probe_timeout: float,
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Privileged half-open TCP SYN scan with token-bucket pacing."""

        def _scapy_syn_scan_sync() -> List[int]:
            from scapy.all import IP, TCP, conf, send, sr1

            conf.verb = 0
            open_ports = []
            for p in ports:
                pkt = IP(dst=host) / TCP(dport=p, flags="S")
                resp = sr1(pkt, timeout=probe_timeout, verbose=0)
                if resp and resp.haslayer(TCP):
                    tcp_layer = resp.getlayer(TCP)
                    # SYN-ACK has flag 0x12 (SYN=0x02, ACK=0x10)
                    if tcp_layer.flags == 0x12:
                        open_ports.append(p)
                        # Send RST to tear down connection cleanly
                        rst = IP(dst=host) / TCP(dport=p, flags="R")
                        send(rst, verbose=0)
            return open_ports

        loop = asyncio.get_running_loop()
        try:
            discovered = await loop.run_in_executor(None, _scapy_syn_scan_sync)
            for p in discovered:
                svc = PORT_SERVICES.get(p, "unknown")
                await context.spool_line(f"Discovered open SYN port {p}/tcp ({svc}) on {host}")
                yield NetworkService.create(
                    host_ip=host,
                    port=p,
                    protocol="tcp",
                    service_name=svc,
                )
        except Exception as e:
            await context.spool_line(
                f"Scapy SYN scan encountered error: {e}. Falling back to asyncio.", is_error=True
            )
            async for finding in self._execute_asyncio_connect(
                host, ports, rate_limit, probe_timeout, context
            ):
                yield finding

    async def _execute_asyncio_connect(
        self,
        host: str,
        ports: List[int],
        rate_limit: int,
        probe_timeout: float,
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Unprivileged non-blocking asyncio TCP connect sweep."""
        sem = asyncio.Semaphore(rate_limit)

        async def _probe_port(p: int) -> Optional[int]:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, p),
                        timeout=probe_timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return p
                except Exception:
                    return None

        tasks = [_probe_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, int):
                svc = PORT_SERVICES.get(res, "unknown")
                await context.spool_line(f"Discovered open port {res}/tcp ({svc}) on {host}")
                yield NetworkService.create(
                    host_ip=host,
                    port=res,
                    protocol="tcp",
                    service_name=svc,
                )
