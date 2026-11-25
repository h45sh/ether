"""SSRF defense and destination verification primitives delegating to ScopeValidator."""

import ipaddress
import socket
from typing import Set

from ether.common.exceptions import PolicyViolationError
from ether.common.scope import METADATA_HOSTNAMES, EngagementScope, ScopeValidator

BLOCKED_TARGET_NAMES: Set[str] = METADATA_HOSTNAMES


def parse_ip_or_host(target: str) -> str:
    """Extract host/IP from URL, URI, or host:port string."""
    return ScopeValidator.parse_host_candidate(target)


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP object falls into any blocked subnet (loopback, metadata, link-local)."""
    verdict = ScopeValidator.is_in_scope(
        str(ip_obj), EngagementScope(), policy_is_unrestricted=False
    )
    return not verdict.allowed


def check_ssrf_safety(target: str) -> None:
    """Resolve target hostname/IP and enforce SSRF defense via ScopeValidator.

    Raises:
        PolicyViolationError: If destination resolves to loopback, link-local, or cloud metadata.
    """
    verdict = ScopeValidator.is_in_scope(target, EngagementScope(), policy_is_unrestricted=False)
    if not verdict.allowed:
        raise PolicyViolationError(f"Target '{target}' blocked by SSRF policy ({verdict.reason}).")

    host = verdict.normalized_target or ""
    if ScopeValidator._parse_ip(host) is not None:
        return

    try:
        addr_info = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return

    for _, _, _, _, sockaddr in addr_info:
        resolved_ip_str = str(sockaddr[0])
        ip_verdict = ScopeValidator.is_in_scope(
            resolved_ip_str, EngagementScope(), policy_is_unrestricted=False
        )
        if not ip_verdict.allowed:
            raise PolicyViolationError(
                f"Target '{target}' resolved to blocked IP {resolved_ip_str} ({ip_verdict.reason})."
            )
