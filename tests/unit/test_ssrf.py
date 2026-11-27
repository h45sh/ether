"""Unit tests verifying SSRF defense and destination verification primitives."""

import ipaddress

import pytest

from ether.common.exceptions import PolicyViolationError
from ether.common.ssrf import check_ssrf_safety, is_ip_blocked, parse_ip_or_host


@pytest.mark.tier0
def test_parse_ip_or_host():
    """Verify parse_ip_or_host extracts hosts across URLs, IP:ports, and IPv6 literals."""
    assert parse_ip_or_host("https://example.com:8443/api/v1?test=1") == "example.com"
    assert parse_ip_or_host("http://192.168.1.100:8080/path") == "192.168.1.100"
    assert parse_ip_or_host("192.168.1.1:9000") == "192.168.1.1"
    assert parse_ip_or_host("[2001:db8::1]:443") == "2001:db8::1"
    assert parse_ip_or_host("target.local/path#ref") == "target.local"
    assert parse_ip_or_host("10.0.0.1") == "10.0.0.1"


@pytest.mark.tier0
def test_is_ip_blocked():
    """Verify is_ip_blocked accurately identifies blocked subnets."""
    # Blocked loopback and link-local
    assert is_ip_blocked(ipaddress.ip_address("127.0.0.1"))
    assert is_ip_blocked(ipaddress.ip_address("127.0.0.254"))
    assert is_ip_blocked(ipaddress.ip_address("169.254.169.254"))
    assert is_ip_blocked(ipaddress.ip_address("::1"))
    assert is_ip_blocked(ipaddress.ip_address("fe80::1"))
    assert is_ip_blocked(ipaddress.ip_address("fd00:ec2::254"))
    assert is_ip_blocked(ipaddress.ip_address("100.100.100.200"))

    # Public safe IPs
    assert not is_ip_blocked(ipaddress.ip_address("8.8.8.8"))
    assert not is_ip_blocked(ipaddress.ip_address("1.1.1.1"))
    assert not is_ip_blocked(ipaddress.ip_address("2606:4700:4700::1111"))


@pytest.mark.tier0
def test_check_ssrf_safety_enforcement():
    """Verify check_ssrf_safety blocks cloud metadata and loopback destinations."""
    # Metadata names and patterns
    with pytest.raises(PolicyViolationError):
        check_ssrf_safety("metadata.google.internal")

    with pytest.raises(PolicyViolationError):
        check_ssrf_safety("http://instance-data/latest/meta-data")

    with pytest.raises(PolicyViolationError):
        check_ssrf_safety("http://169.254.169.254/latest/meta-data")

    with pytest.raises(PolicyViolationError):
        check_ssrf_safety("http://127.0.0.1:8080")

    with pytest.raises(PolicyViolationError):
        check_ssrf_safety("http://[::1]:8080")

    with pytest.raises(PolicyViolationError):
        check_ssrf_safety("")

    # Public IP destination should pass
    check_ssrf_safety("8.8.8.8")
