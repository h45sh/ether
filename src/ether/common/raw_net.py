"""Deep module encapsulating ambient raw socket packet crafting and stealth probing."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence, Set

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


@dataclass
class ServiceProbeResult:
    """Normalized port prober result."""

    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = "unknown"
    state: str = "open"


class RawNetworkGovernor:
    """Supervisor for raw socket acceleration and unprivileged connect fallbacks."""

    @staticmethod
    def has_raw_capability() -> bool:
        return has_raw_socket_capability()

    @classmethod
    async def fast_syn_sweep(
        cls,
        target: str,
        ports: Sequence[int],
        timeout_sec: float = 2.0,
        rate_limit: int = 500,
        force_unprivileged: bool = False,
    ) -> AsyncIterator[ServiceProbeResult]:
        """Perform high-performance TCP SYN sweep with automatic asyncio.open_connection fallback."""
        is_privileged = cls.has_raw_capability() and not force_unprivileged
        port_list = list(ports) if ports else list(COMMON_PORTS)

        if is_privileged:
            async for res in cls._scapy_syn_sweep(target, port_list, timeout_sec, rate_limit):
                yield res
        else:
            async for res in cls._asyncio_connect_sweep(target, port_list, timeout_sec, rate_limit):
                yield res

    @classmethod
    async def _scapy_syn_sweep(
        cls,
        target: str,
        ports: List[int],
        timeout_sec: float,
        rate_limit: int,
    ) -> AsyncIterator[ServiceProbeResult]:
        def _sync_scapy() -> List[int]:
            from scapy.all import IP, TCP, conf, send, sr1  # type: ignore[attr-defined]

            conf.verb = 0
            open_ports = []
            for p in ports:
                pkt = IP(dst=target) / TCP(dport=p, flags="S")
                resp = sr1(pkt, timeout=timeout_sec, verbose=0)
                if resp and resp.haslayer(TCP):
                    tcp_layer = resp.getlayer(TCP)
                    if tcp_layer is not None and tcp_layer.flags == 0x12:
                        open_ports.append(p)
                        rst = IP(dst=target) / TCP(dport=p, flags="R")
                        send(rst, verbose=0)
            return open_ports

        loop = asyncio.get_running_loop()
        try:
            discovered = await loop.run_in_executor(None, _sync_scapy)
            for p in discovered:
                yield ServiceProbeResult(
                    host=target,
                    port=p,
                    protocol="tcp",
                    service_name=PORT_SERVICES.get(p, "unknown"),
                    state="open",
                )
        except Exception:
            # On scapy error, fall back cleanly to asyncio connect
            async for res in cls._asyncio_connect_sweep(target, ports, timeout_sec, rate_limit):
                yield res

    @classmethod
    async def _asyncio_connect_sweep(
        cls,
        target: str,
        ports: List[int],
        timeout_sec: float,
        rate_limit: int,
    ) -> AsyncIterator[ServiceProbeResult]:
        sem = asyncio.Semaphore(max(1, rate_limit))

        async def _probe(p: int) -> Optional[int]:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, p),
                        timeout=timeout_sec,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return p
                except Exception:
                    return None

        tasks = [_probe(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, int):
                yield ServiceProbeResult(
                    host=target,
                    port=res,
                    protocol="tcp",
                    service_name=PORT_SERVICES.get(res, "unknown"),
                    state="open",
                )
