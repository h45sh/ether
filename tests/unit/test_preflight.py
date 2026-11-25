"""Unit tests for preflight dependency, capability, and parameter verification in Ether."""

from types import SimpleNamespace
from typing import Optional

import pytest

from ether.gateway.gate import GatePolicy
from ether.gateway.preflight import (
    PreflightVerifier,
    get_tool_target_guidance,
)
from ether.registry.registry import ToolRegistry

pytestmark = pytest.mark.fast


class FakeToolAdapter:
    def __init__(
        self,
        name: str,
        is_installed: bool = True,
        binary: Optional[str] = None,
        target_types: Optional[list[str]] = None,
    ):
        self.name = name
        self._installed = is_installed
        self.binary = binary or name
        self.target_types = target_types

    def validate_install(self) -> bool:
        return self._installed


class FakeRegistry:
    def __init__(self, tools: dict):
        self._tools = tools

    def get_tool(self, name: str):
        if name in self._tools:
            adapter = self._tools[name]
            manifest = (
                SimpleNamespace(input={"target_types": adapter.target_types})
                if getattr(adapter, "target_types", None)
                else None
            )
            return {"adapter": adapter, "manifest": manifest}
        return None


def test_preflight_missing_tool():
    verifier = PreflightVerifier()
    report = verifier.verify(tool_name="", target="127.0.0.1")
    assert not report.is_valid
    assert any(
        i.category == "binary" and "No security tool selected" in i.title for i in report.errors
    )


def test_preflight_binary_missing_provides_install_hint():
    fake_adapter = FakeToolAdapter("gobuster", is_installed=False)
    registry = FakeRegistry({"gobuster": fake_adapter})
    verifier = PreflightVerifier(registry=registry)

    report = verifier.verify(tool_name="gobuster", target="http://127.0.0.1:8888")
    assert not report.is_valid
    binary_errors = [i for i in report.errors if i.category == "binary"]
    assert len(binary_errors) == 1
    assert "gobuster" in binary_errors[0].title
    assert "apt install gobuster" in binary_errors[0].remediation_hint
    assert binary_errors[0].can_auto_remedy
    assert binary_errors[0].remedy_action == "copy_install_command"


def test_preflight_dnspython_always_valid():
    verifier = PreflightVerifier()
    report = verifier.verify(tool_name="dnspython", target="example.com")
    assert not any(i.category == "binary" for i in report.issues)


def test_preflight_empty_target_and_remedy():
    fake_adapter = FakeToolAdapter("nmap", is_installed=True)
    registry = FakeRegistry({"nmap": fake_adapter})
    verifier = PreflightVerifier(registry=registry)

    report = verifier.verify(tool_name="nmap", target="")
    assert not report.is_valid
    target_errors = [i for i in report.errors if i.category == "target"]
    assert len(target_errors) == 1
    assert target_errors[0].can_auto_remedy
    assert target_errors[0].remedy_action == "set_default_target"

    # Apply remedy
    new_target, new_flags, feedback = verifier.apply_remedy(
        target_errors[0], target="", flags="-sV"
    )
    assert new_target == "scanme.nmap.org"
    assert "scanme.nmap.org" in feedback


def test_preflight_unexpanded_placeholder_variable():
    verifier = PreflightVerifier()
    report = verifier.verify(tool_name="nmap", target="$TARGET")
    assert not report.is_valid
    assert any("Unexpanded variable placeholder" in i.title for i in report.errors)


def test_preflight_web_tool_missing_http_scheme():
    fake_adapter = FakeToolAdapter("gobuster", is_installed=True, target_types=["url"])
    registry = FakeRegistry({"gobuster": fake_adapter})
    verifier = PreflightVerifier(registry=registry)

    report = verifier.verify(tool_name="gobuster", target="192.168.1.100")
    assert not report.is_valid
    scheme_errors = [i for i in report.errors if i.category == "target"]
    assert len(scheme_errors) == 1
    assert "requires an HTTP/HTTPS URL" in scheme_errors[0].title
    assert scheme_errors[0].can_auto_remedy

    # Apply remedy
    new_target, _, feedback = verifier.apply_remedy(
        scheme_errors[0], target="192.168.1.100", flags=""
    )
    assert new_target == "http://192.168.1.100"
    assert "Updated target to" in feedback


def test_preflight_network_tool_with_url_warning():
    fake_adapter = FakeToolAdapter(
        "nmap", is_installed=True, target_types=["ip", "cidr", "domain"]
    )
    registry = FakeRegistry({"nmap": fake_adapter})
    verifier = PreflightVerifier(registry=registry)

    report = verifier.verify(tool_name="nmap", target="https://192.168.1.50:8443/login")
    assert report.is_valid  # Warnings are non-blocking
    assert report.has_warnings
    warns = [i for i in report.warnings if i.category == "target"]
    assert len(warns) == 1
    assert "expects a host or IP" in warns[0].title

    # Apply remedy
    new_target, _, feedback = verifier.apply_remedy(
        warns[0], target="https://192.168.1.50:8443/login", flags=""
    )
    assert new_target == "192.168.1.50"
    assert "Stripped URL scheme" in feedback


def test_preflight_sudo_policy_seam():
    fake_adapter = FakeToolAdapter("nmap", is_installed=True)
    registry = FakeRegistry({"nmap": fake_adapter})

    # Under SAFE policy: sudo is blocked
    safe_verifier = PreflightVerifier(registry=registry, policy=GatePolicy.SAFE)
    safe_report = safe_verifier.verify("nmap", target="scanme.nmap.org", flags="sudo -sS")
    assert not safe_report.is_valid
    assert any("sudo" in i.title.lower() for i in safe_report.errors)

    # Apply remedy
    issue = next(i for i in safe_report.errors if "sudo" in i.title.lower())
    _, new_flags, msg = safe_verifier.apply_remedy(issue, target="scanme.nmap.org", flags="sudo -sS")
    assert "sudo" not in new_flags

    # Under UNRESTRICTED policy: sudo is allowed
    unres_verifier = PreflightVerifier(registry=registry, policy=GatePolicy.UNRESTRICTED)
    unres_report = unres_verifier.verify("nmap", target="scanme.nmap.org", flags="sudo -sS")
    assert unres_report.is_valid
    assert not any("sudo" in i.title.lower() for i in unres_report.errors)


def test_preflight_ssrf_metadata_policy_seam():
    fake_adapter = FakeToolAdapter("nmap", is_installed=True)
    registry = FakeRegistry({"nmap": fake_adapter})

    # Under SAFE policy: metadata is blocked
    safe_verifier = PreflightVerifier(registry=registry, policy=GatePolicy.SAFE)
    safe_report = safe_verifier.verify("nmap", target="169.254.169.254")
    assert not safe_report.is_valid
    assert any("blocked by security policy" in i.title for i in safe_report.errors)

    # Under UNRESTRICTED policy: allowed
    unres_verifier = PreflightVerifier(registry=registry, policy=GatePolicy.UNRESTRICTED)
    unres_report = unres_verifier.verify("nmap", target="169.254.169.254")
    assert unres_report.is_valid
    assert not any("blocked by security policy" in i.title for i in unres_report.errors)


def test_preflight_wordlist_macro_unseeded_remedy(tmp_path):
    dest_dir = str(tmp_path / "wordlists")
    verifier = PreflightVerifier(wordlists_dir=dest_dir)

    report = verifier.verify("gobuster", target="http://127.0.0.1:8080", flags="-w @common.txt")
    wordlist_warns = [i for i in report.warnings if i.category == "wordlist"]
    assert len(wordlist_warns) == 1
    assert "is not yet seeded" in wordlist_warns[0].title
    assert wordlist_warns[0].can_auto_remedy

    # Apply remedy
    t, f, msg = verifier.apply_remedy(
        wordlist_warns[0], target="http://127.0.0.1:8080", flags="-w @common.txt"
    )
    assert "Extracted" in msg
    assert t == "http://127.0.0.1:8080"


def test_default_tool_targets_coverage_and_preflight():
    """Verify all tools in registry have dynamic target guidance and pass preflight on valid targets."""
    registry = ToolRegistry()
    registry.load_tools()
    verifier = PreflightVerifier(registry=registry)

    assert len(registry.tools) > 0
    for tool_name in registry.tools:
        target_types = verifier._get_tool_target_types(tool_name)
        if "url" in target_types and not any(t in target_types for t in ("ip", "cidr")):
            target = "http://scanme.nmap.org"
        elif "domain" in target_types and "ip" not in target_types:
            target = "example.com"
        else:
            target = "scanme.nmap.org"

        report = verifier.verify(tool_name, target=target, flags="")
        non_binary_errors = [
            i for i in report.issues if i.severity == "error" and i.category != "binary"
        ]
        assert not non_binary_errors, (
            f"Tool {tool_name} failed preflight on dynamic target {target}: {non_binary_errors}"
        )

        guidance = get_tool_target_guidance(tool_name)
        assert bool(guidance)
        assert "Target Scope" in guidance
        assert "Permissible & Effective Targets" in guidance
        assert "Strictly Prohibited & Dangerous Targets" in guidance
        assert guidance.count("## Operational Precautions & Ethics") == 1


def test_preflight_loopback_adr0012_and_no_legacy_constants():
    import ether.gateway.preflight as preflight_mod
    from ether.gateway.scope import EngagementScope

    for legacy_name in (
        "WEB_TOOLS",
        "NETWORK_TOOLS",
        "DOMAIN_TOOLS",
        "WORDLIST_TOOLS",
        "TOOL_TARGET_GUIDANCE",
    ):
        assert not hasattr(preflight_mod, legacy_name)

    fake_adapter = FakeToolAdapter("nmap", is_installed=True)
    registry = FakeRegistry({"nmap": fake_adapter})

    # Default SAFE blocks loopback
    verifier_default = PreflightVerifier(registry=registry, policy=GatePolicy.SAFE)
    rep_blocked = verifier_default.verify("nmap", target="127.0.0.1")
    assert not rep_blocked.is_valid
    assert any(i.category == "security" for i in rep_blocked.errors)

    # Explicit allow_loopback=True permits loopback
    verifier_loop = PreflightVerifier(
        registry=registry,
        policy=GatePolicy.SAFE,
        scope=EngagementScope(allow_loopback=True),
    )
    rep_allowed = verifier_loop.verify("nmap", target="127.0.0.1")
    assert not any(i.category == "security" for i in rep_allowed.errors)
