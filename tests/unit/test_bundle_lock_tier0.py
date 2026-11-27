"""Tier 0 drift gate verifying tools/bundle_lock.json matches all bundled tools/*."""

from __future__ import annotations

import json

import pytest

from ether.registry.loader import PluginLoader, PluginTrustMode
from scripts.update_bundle_lock import LOCK_PATH, TOOLS_DIR, build_lock_payload


@pytest.mark.tier0
def test_bundle_lock_is_up_to_date():
    """Ensure tools/bundle_lock.json matches every tools/*/manifest.toml and adapter.py."""
    assert LOCK_PATH.is_file(), "Missing tools/bundle_lock.json; run scripts/update_bundle_lock.py"
    current = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    expected = build_lock_payload(TOOLS_DIR)
    assert current == expected, (
        "tools/bundle_lock.json is out of date. Run: .venv/bin/python scripts/update_bundle_lock.py"
    )


@pytest.mark.tier0
def test_bundled_core_adapters_load_in_strict_mode():
    """First-party bundled adapters load under PluginTrustMode.STRICT without .py.sig sidecars."""
    loader = PluginLoader(trust_mode=PluginTrustMode.STRICT)
    for name in ("tls_probe", "http_probe", "nmap"):
        tool_dir = TOOLS_DIR / name
        adapter = loader.load_verified_adapter(tool_dir / "adapter.py", tool_dir / "manifest.toml")
        assert adapter is not None
