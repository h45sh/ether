"""SSRF defense and destination verification primitives."""

import ipaddress
import socket
import urllib.parse
from typing import Set

from ether.common.algorithms import IPRadixTrie
from ether.common.exceptions import PolicyViolationError

BLOCKED_TARGET_NAMES: Set[str] = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # IPv4 Loopback
    ipaddress.ip_network("::1/128"),  # IPv6 Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 Link-Local / Cloud Metadata
    ipaddress.ip_network("fe80::/10"),  # IPv6 Link-Local
    ipaddress.ip_network("fd00:ec2::/64"),  # AWS IPv6 IMDSv2 metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
]

_BLOCKED_TRIE = IPRadixTrie()
for _net in BLOCKED_NETWORKS:
    _BLOCKED_TRIE.insert(_net)


def parse_ip_or_host(target: str) -> str:
    """Extract host/IP from URL, URI, or host:port string."""
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or parsed.netloc
    else:
        host = target.split("/")[0].split("?")[0].split("#")[0]
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        elif ":" in host and host.count(":") == 1:
            host = host.split(":")[0]
    return host.strip("[]")


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP object falls into any blocked subnet (loopback, metadata, link-local)."""
    if hasattr(ip_obj, "ipv4_mapped") and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped
    return _BLOCKED_TRIE.contains(ip_obj)


def check_ssrf_safety(target: str) -> None:
    """Resolve target hostname/IP and enforce SSRF defense.

    Raises:
        PolicyViolationError: If destination resolves to loopback, link-local, or cloud metadata.
    """
    host = parse_ip_or_host(target).lower()
    if not host:
        raise PolicyViolationError("Empty or invalid target destination.")

    if host in BLOCKED_TARGET_NAMES or any(b in host for b in ("169.254.", "metadata.")):
        raise PolicyViolationError(
            f"Target '{target}' blocked by SSRF policy (metadata keyword match)."
        )

    # Try direct IP parse
    try:
        ip_obj = ipaddress.ip_address(host)
        if is_ip_blocked(ip_obj):
            raise PolicyViolationError(f"Target '{target}' ({ip_obj}) blocked by SSRF policy.")
        return
    except ValueError:
        pass

    # Resolve hostname to all IP addresses
    try:
        addr_info = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # If DNS cannot be resolved, let caller handle or reject
        return

    for _, _, _, _, sockaddr in addr_info:
        resolved_ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(resolved_ip_str)
            if is_ip_blocked(ip_obj):
                raise PolicyViolationError(
                    f"Target '{target}' resolved to blocked IP {resolved_ip_str} (SSRF defense)."
                )
        except ValueError:
            continue
