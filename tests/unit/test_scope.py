"""Unit tests for deep ScopeValidator and EngagementScope RoE module."""

import pytest

from ether.gateway.scope import EngagementScope, ScopeValidator

pytestmark = pytest.mark.fast


def test_scope_metadata_blocking():
    scope = EngagementScope()
    # Metadata IP blocked under default safe policy
    verdict = ScopeValidator.is_in_scope("169.254.169.254", scope, policy_is_unrestricted=False)
    assert not verdict.allowed
    assert verdict.reason == "BLOCKED_CLOUD_METADATA"

    # Metadata hostname blocked
    v_host = ScopeValidator.is_in_scope("metadata.google.internal", scope, policy_is_unrestricted=False)
    assert not v_host.allowed
    assert v_host.reason == "BLOCKED_CLOUD_METADATA"

    # Allowed with audit warning under UNRESTRICTED policy
    v_unrestricted = ScopeValidator.is_in_scope("169.254.169.254", scope, policy_is_unrestricted=True)
    assert v_unrestricted.allowed
    assert v_unrestricted.reason == "WARNING_METADATA_ALLOWED_BY_POLICY"


def test_scope_loopback_handling():
    scope_no_loopback = EngagementScope(allow_loopback=False)
    v_blocked = ScopeValidator.is_in_scope("127.0.0.1", scope_no_loopback)
    assert not v_blocked.allowed
    assert v_blocked.reason == "BLOCKED_LOOPBACK_UNAUTHORIZED"

    scope_with_loopback = EngagementScope(allow_loopback=True)
    v_allowed = ScopeValidator.is_in_scope("127.0.0.1", scope_with_loopback)
    assert v_allowed.allowed
    assert v_allowed.reason == "ALLOWED_IN_SCOPE_IP"


def test_scope_cidr_radix_trie_matching():
    scope = EngagementScope(allowed_cidrs=["10.10.0.0/16", "192.168.1.0/24"])

    # In scope
    v1 = ScopeValidator.is_in_scope("10.10.5.23", scope)
    assert v1.allowed
    assert v1.reason == "ALLOWED_IN_SCOPE_IP"

    v2 = ScopeValidator.is_in_scope("192.168.1.100", scope)
    assert v2.allowed
    assert v2.reason == "ALLOWED_IN_SCOPE_IP"

    # Out of scope IP
    v3 = ScopeValidator.is_in_scope("172.16.0.1", scope, policy_is_unrestricted=False)
    assert not v3.allowed
    assert v3.reason == "OUT_OF_SCOPE_CIDR"

    # Out of scope under UNRESTRICTED
    v3_unrestricted = ScopeValidator.is_in_scope("172.16.0.1", scope, policy_is_unrestricted=True)
    assert v3_unrestricted.allowed
    assert v3_unrestricted.reason == "WARNING_OUT_OF_SCOPE_ALLOWED_BY_POLICY"


def test_scope_domain_wildcard_matching():
    scope = EngagementScope(allowed_domains=["*.target.corp", "api.example.com"])

    v1 = ScopeValidator.is_in_scope("sub.target.corp", scope)
    assert v1.allowed
    assert v1.reason == "ALLOWED_IN_SCOPE_DOMAIN"

    v2 = ScopeValidator.is_in_scope("api.example.com", scope)
    assert v2.allowed
    assert v2.reason == "ALLOWED_IN_SCOPE_DOMAIN"

    v3 = ScopeValidator.is_in_scope("evil.com", scope, policy_is_unrestricted=False)
    assert not v3.allowed
    assert v3.reason == "OUT_OF_SCOPE_DOMAIN"


def test_scope_url_and_port_stripping():
    scope = EngagementScope(allowed_cidrs=["10.0.0.0/8"])
    v = ScopeValidator.is_in_scope("http://10.20.30.40:8080/admin/path", scope)
    assert v.allowed
    assert v.normalized_target == "10.20.30.40"


def test_scope_metadata_internal_and_alternate_ip_notations():
    scope = EngagementScope()
    v_meta = ScopeValidator.is_in_scope("http://metadata.internal/computeMetadata/v1/", scope)
    assert not v_meta.allowed
    assert v_meta.reason == "BLOCKED_CLOUD_METADATA"

    v_hex = ScopeValidator.is_in_scope("http://0xa9fea9fe/latest/meta-data", scope)
    assert not v_hex.allowed
    assert v_hex.reason == "BLOCKED_CLOUD_METADATA"
    assert v_hex.normalized_target == "169.254.169.254"

    v_dec = ScopeValidator.is_in_scope("2852039166", scope)
    assert not v_dec.allowed
    assert v_dec.reason == "BLOCKED_CLOUD_METADATA"
    assert v_dec.normalized_target == "169.254.169.254"


@pytest.mark.asyncio
async def test_scope_check_destination_with_dns_resolver():
    async def resolve_metadata(_host: str):
        return ["169.254.169.254"]

    v_meta = await ScopeValidator.check_destination(
        "https://rebind.evil.com/latest",
        EngagementScope(),
        dns_resolver=resolve_metadata,
    )
    assert not v_meta.allowed
    assert v_meta.reason == "BLOCKED_CLOUD_METADATA"

    async def resolve_loopback(_host: str):
        return ["127.0.0.1"]

    v_loop_blocked = await ScopeValidator.check_destination(
        "localtest.me",
        EngagementScope(allow_loopback=False),
        dns_resolver=resolve_loopback,
    )
    assert not v_loop_blocked.allowed
    assert v_loop_blocked.reason == "BLOCKED_LOOPBACK_UNAUTHORIZED"

    v_loop_allowed = await ScopeValidator.check_destination(
        "localtest.me",
        EngagementScope(allow_loopback=True),
        dns_resolver=resolve_loopback,
    )
    assert v_loop_allowed.allowed

    v_loop_unrestricted = await ScopeValidator.check_destination(
        "localtest.me",
        EngagementScope(allow_loopback=False),
        policy_is_unrestricted=True,
        dns_resolver=resolve_loopback,
    )
    assert v_loop_unrestricted.allowed
    assert v_loop_unrestricted.reason == "WARNING_LOOPBACK_ALLOWED_BY_POLICY"

    async def resolve_public(_host: str):
        return ["93.184.216.34"]

    v_pub = await ScopeValidator.check_destination(
        "example.com",
        EngagementScope(),
        dns_resolver=resolve_public,
    )
    assert v_pub.allowed
    assert v_pub.reason == "ALLOWED_IN_SCOPE_DOMAIN"
