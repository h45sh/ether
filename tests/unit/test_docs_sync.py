"""Tier 0 verification that generated configuration and tool catalog docs match live code."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.tier0
def test_generated_docs_in_sync():
    """Verify docs/reference/configuration.md and tools-catalog.md are up to date."""
    script = ROOT / "scripts" / "generate_docs.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"Reference docs are out of sync. Run `python scripts/generate_docs.py`.\n{proc.stderr}"
    )
