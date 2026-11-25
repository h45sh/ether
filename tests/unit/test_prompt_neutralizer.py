"""Unit tests for defensive prompt neutralization in ActionGateway and PromptNeutralizer."""

import pytest

from ether.gateway.neutralizer import PromptNeutralizer


@pytest.mark.fast
def test_prompt_neutralizer_translation():
    raw_prompt = (
        "Find RCE vulnerabilities to exploit the target, crack passwords, and bypass firewalls."
    )
    neutralized = PromptNeutralizer.neutralize(raw_prompt)

    assert "exploit" not in neutralized.lower()
    assert "crack" not in neutralized.lower()
    assert "bypass" not in neutralized.lower()
    assert "verify vulnerability impact" in neutralized
    assert "audit credential resilience" in neutralized
    assert "evaluate perimeter filter policy" in neutralized


@pytest.mark.fast
def test_prompt_neutralizer_preserves_technical_identifiers():
    raw_prompt = (
        "Audit attack surface for 192.168.1.100 and sub.example.com with --flags exploit=false"
    )
    neutralized = PromptNeutralizer.neutralize(raw_prompt)

    # IPs, domains, flags preserved
    assert "192.168.1.100" in neutralized
    assert "sub.example.com" in neutralized
    assert "external assessment perimeter" in neutralized
