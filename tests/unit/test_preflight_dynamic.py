"""Unit tests for dynamic manifest-driven target format validation in PreflightVerifier."""

from typing import List, Optional

import pytest

from ether.gateway.preflight import PreflightVerifier
from ether.registry.manifest import Manifest


class MockToolAdapter:
    def __init__(self, name: str, is_installed: bool = True):
        self.name = name
        self._installed = is_installed
        self.binary = name

    def validate_install(self) -> bool:
        return self._installed


class MockManifestRegistry:
    def __init__(self, tools: dict):
        self._tools = tools

    def get_tool(self, name: str):
        return self._tools.get(name)


def make_tool_manifest(
    name: str, accepts: List[str], target_types: Optional[List[str]] = None
) -> Manifest:
    data = {
        "meta": {
            "name": name,
            "description": f"Test tool {name}",
            "categories": ["recon"],
            "binary": name,
        },
        "modes": {"learning": True, "power": True},
        "input": {"accepts": accepts},
        "output": {"produces": []},
    }
    if target_types is not None:
        data["input"]["target_types"] = target_types
    return Manifest.model_validate(data)


@pytest.mark.fast
def test_manifest_driven_url_target_validation():
    """Verify tool with target_types=['url'] requires http/https scheme."""
    manifest = make_tool_manifest("custom_web", accepts=["web.endpoint"], target_types=["url"])
    adapter = MockToolAdapter("custom_web")
    registry = MockManifestRegistry({"custom_web": {"adapter": adapter, "manifest": manifest}})

    verifier = PreflightVerifier(registry=registry)
    # Target missing scheme should be flagged as error
    report = verifier.verify("custom_web", "10.0.0.1")
    assert not report.is_valid
    assert any("requires an HTTP/HTTPS URL" in e.title for e in report.errors)

    # With scheme should be valid
    valid_report = verifier.verify("custom_web", "https://10.0.0.1")
    assert valid_report.is_valid


@pytest.mark.fast
def test_manifest_driven_hybrid_target_validation():
    """Verify hybrid tool with target_types=['url', 'ip', 'domain'] accepts both URLs and bare IPs."""
    manifest = make_tool_manifest(
        "hybrid_prober",
        accepts=["web.endpoint", "network.host"],
        target_types=["url", "ip", "domain"],
    )
    adapter = MockToolAdapter("hybrid_prober")
    registry = MockManifestRegistry({"hybrid_prober": {"adapter": adapter, "manifest": manifest}})

    verifier = PreflightVerifier(registry=registry)

    # Bare IP should be valid for hybrid prober
    report_ip = verifier.verify("hybrid_prober", "192.168.1.1")
    assert report_ip.is_valid

    # URL should also be valid for hybrid prober
    report_url = verifier.verify("hybrid_prober", "http://192.168.1.1:8080")
    assert report_url.is_valid

    # Domain should be valid for hybrid prober
    report_domain = verifier.verify("hybrid_prober", "scanme.nmap.org")
    assert report_domain.is_valid


@pytest.mark.fast
def test_manifest_driven_network_target_rejects_url():
    """Verify network tool with target_types=['ip', 'cidr', 'domain'] warns on URL."""
    manifest = make_tool_manifest(
        "custom_port_scanner",
        accepts=["network.host"],
        target_types=["ip", "cidr", "domain"],
    )
    adapter = MockToolAdapter("custom_port_scanner")
    registry = MockManifestRegistry(
        {"custom_port_scanner": {"adapter": adapter, "manifest": manifest}}
    )

    verifier = PreflightVerifier(registry=registry)

    report = verifier.verify("custom_port_scanner", "http://192.168.1.1/api")
    assert any("expects a host or IP, not a URL" in w.title for w in report.warnings)


@pytest.mark.fast
def test_dynamic_fallback_without_static_sets():
    """Verify unknown tool not in static sets derives validation dynamically from accepts schemas."""
    manifest = make_tool_manifest("brand_new_scanner", accepts=["network.host"])
    adapter = MockToolAdapter("brand_new_scanner")
    registry = MockManifestRegistry(
        {"brand_new_scanner": {"adapter": adapter, "manifest": manifest}}
    )

    verifier = PreflightVerifier(registry=registry)

    # Valid IP
    report = verifier.verify("brand_new_scanner", "10.10.10.10")
    assert report.is_valid

    # URL yields warning
    report_url = verifier.verify("brand_new_scanner", "http://10.10.10.10")
    assert any("expects a host or IP, not a URL" in w.title for w in report_url.warnings)
