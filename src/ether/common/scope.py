"""Deep Rules of Engagement (RoE) Scope and Target Authorization Module.

Encapsulates CIDR Radix Trie matching, FQDN wildcard globbing, loopback/private
filtering, cloud IMDS/metadata boundary enforcement, and pre-connect async DNS
resolution.
"""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, NamedTuple, Optional, Union
from urllib.parse import urlparse

from ether.common.algorithms import IPRadixTrie

logger = logging.getLogger(__name__)

# Cloud metadata addresses strictly blocked under GatePolicy.SAFE
METADATA_IPS = {
    "169.254.169.254",  # AWS IMDS / Azure / GCP
    "fd00:ec2::254",  # AWS IPv6 IMDS
    "100.100.100.200",  # Alibaba Cloud metadata
}
METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}


class ScopeVerdict(NamedTuple):
    allowed: bool
    reason: str
    normalized_target: Optional[str] = None


@dataclass
class EngagementScope:
    """Declared boundary rules for an engagement session."""

    allowed_cidrs: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    allow_loopback: bool = False
    allow_metadata: bool = False
    allow_link_local: bool = False


class ScopeValidator:
    """Deep module validating targets against engagement boundaries and cloud metadata gates."""

    @classmethod
    def parse_host_candidate(cls, target: str) -> str:
        """Extract bare host (IP or FQDN) from target string, stripping schemes/ports/paths."""
        clean = target.strip()
        if "://" in clean:
            parsed = urlparse(clean)
            return parsed.hostname or clean
        if clean.startswith("[") and "]" in clean:
            return clean[1 : clean.index("]")]
        if ":" in clean and not clean.count(":") > 1:
            return clean.split(":")[0]
        if "/" in clean and not (
            "/" in clean and clean.count("/") == 1 and clean.split("/")[1].isdigit()
        ):
            return clean.split("/")[0]
        return clean

    @classmethod
    def _parse_ip(
        cls, host: str
    ) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """Parse standard IP, CIDR network address, or alternate numerical IP (hex/decimal/octal)."""
        ip_obj: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = None
        try:
            if "/" in host:
                net_obj = ipaddress.ip_network(host, strict=False)
                ip_obj = net_obj.network_address
            else:
                ip_obj = ipaddress.ip_address(host)
        except ValueError:
            try:
                ip_obj = ipaddress.IPv4Address(socket.inet_aton(host))
            except OSError:
                ip_obj = None

        if ip_obj is not None and hasattr(ip_obj, "ipv4_mapped") and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        return ip_obj

    @classmethod
    def is_in_scope(
        cls,
        target: str,
        scope: Optional[EngagementScope] = None,
        policy_is_unrestricted: bool = False,
    ) -> ScopeVerdict:
        """Evaluate target against engagement scope, returning a structured ScopeVerdict."""
        if not target or not target.strip():
            return ScopeVerdict(allowed=False, reason="EMPTY_TARGET", normalized_target=None)

        active_scope = scope if scope is not None else EngagementScope()
        host = cls.parse_host_candidate(target)
        lower_host = host.lower()

        # 1. Cloud Metadata Defense (hostnames)
        if not active_scope.allow_metadata:
            if lower_host in METADATA_HOSTNAMES or any(
                b in lower_host for b in ("169.254.", "metadata.")
            ):
                if policy_is_unrestricted:
                    return ScopeVerdict(
                        allowed=True,
                        reason="WARNING_METADATA_ALLOWED_BY_POLICY",
                        normalized_target=host,
                    )
                return ScopeVerdict(
                    allowed=False, reason="BLOCKED_CLOUD_METADATA", normalized_target=host
                )

        ip_obj = cls._parse_ip(host)

        if ip_obj is not None:
            # Check Metadata IP
            if str(ip_obj) in METADATA_IPS and not active_scope.allow_metadata:
                if policy_is_unrestricted:
                    return ScopeVerdict(
                        allowed=True,
                        reason="WARNING_METADATA_ALLOWED_BY_POLICY",
                        normalized_target=str(ip_obj),
                    )
                return ScopeVerdict(
                    allowed=False, reason="BLOCKED_CLOUD_METADATA", normalized_target=str(ip_obj)
                )

            # Check Loopback
            if ip_obj.is_loopback and not active_scope.allow_loopback:
                if policy_is_unrestricted:
                    return ScopeVerdict(
                        allowed=True,
                        reason="WARNING_LOOPBACK_ALLOWED_BY_POLICY",
                        normalized_target=str(ip_obj),
                    )
                return ScopeVerdict(
                    allowed=False,
                    reason="BLOCKED_LOOPBACK_UNAUTHORIZED",
                    normalized_target=str(ip_obj),
                )

            # Check Link-Local
            if (
                ip_obj.is_link_local
                and not active_scope.allow_link_local
                and not active_scope.allow_metadata
            ):
                if policy_is_unrestricted:
                    return ScopeVerdict(
                        allowed=True,
                        reason="WARNING_LINK_LOCAL_ALLOWED_BY_POLICY",
                        normalized_target=str(ip_obj),
                    )
                return ScopeVerdict(
                    allowed=False, reason="BLOCKED_LINK_LOCAL", normalized_target=str(ip_obj)
                )

            # Check allowed CIDRs if specified
            if active_scope.allowed_cidrs:
                trie = IPRadixTrie()
                for cidr in active_scope.allowed_cidrs:
                    try:
                        trie.insert(cidr)
                    except ValueError:
                        pass
                if not trie.contains(ip_obj):
                    if policy_is_unrestricted:
                        return ScopeVerdict(
                            allowed=True,
                            reason="WARNING_OUT_OF_SCOPE_ALLOWED_BY_POLICY",
                            normalized_target=str(ip_obj),
                        )
                    return ScopeVerdict(
                        allowed=False, reason="OUT_OF_SCOPE_CIDR", normalized_target=str(ip_obj)
                    )

            return ScopeVerdict(
                allowed=True, reason="ALLOWED_IN_SCOPE_IP", normalized_target=str(ip_obj)
            )

        # 2. Domain / Hostname Matching
        if active_scope.allowed_domains:
            matched = False
            for pattern in active_scope.allowed_domains:
                if fnmatch.fnmatch(lower_host, pattern.lower()):
                    matched = True
                    break
            if not matched:
                if policy_is_unrestricted:
                    return ScopeVerdict(
                        allowed=True,
                        reason="WARNING_OUT_OF_SCOPE_ALLOWED_BY_POLICY",
                        normalized_target=host,
                    )
                return ScopeVerdict(
                    allowed=False, reason="OUT_OF_SCOPE_DOMAIN", normalized_target=host
                )

        return ScopeVerdict(
            allowed=True, reason="ALLOWED_IN_SCOPE_DOMAIN", normalized_target=host
        )

    @classmethod
    async def check_destination(
        cls,
        target: str,
        scope: Optional[EngagementScope] = None,
        policy_is_unrestricted: bool = False,
        dns_resolver: Optional[Callable[[str], Awaitable[List[str]]]] = None,
    ) -> ScopeVerdict:
        """Async pre-connect destination check with DNS resolution and injectable resolver."""
        verdict = cls.is_in_scope(
            target, scope=scope, policy_is_unrestricted=policy_is_unrestricted
        )
        if not verdict.allowed or not verdict.normalized_target:
            return verdict

        # Already an IP / CIDR — no DNS lookup needed
        if cls._parse_ip(verdict.normalized_target) is not None:
            return verdict

        host = verdict.normalized_target
        resolved_ips: List[str] = []
        if dns_resolver is not None:
            resolved_ips = await dns_resolver(host)
        else:
            try:
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(host, None)
                seen = set()
                for entry in addr_info:
                    ip_str = entry[4][0]
                    if ip_str not in seen:
                        seen.add(ip_str)
                        resolved_ips.append(ip_str)
            except OSError:
                return verdict

        warning_verdict: Optional[ScopeVerdict] = None
        for ip_str in resolved_ips:
            ip_verdict = cls.is_in_scope(
                ip_str, scope=scope, policy_is_unrestricted=policy_is_unrestricted
            )
            if not ip_verdict.allowed:
                return ip_verdict
            if ip_verdict.reason.startswith("WARNING_") and warning_verdict is None:
                warning_verdict = ip_verdict

        return warning_verdict if warning_verdict is not None else verdict
