#!/usr/bin/env python3
"""Generate or verify tools/bundle_lock.json for first-party bundled adapters."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
LOCK_PATH = TOOLS_DIR / "bundle_lock.json"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_lock_payload(tools_dir: Path = TOOLS_DIR) -> dict:
    """Compute deterministic SHA-256 lockfile payload for all bundled tools/*."""
    adapters: dict[str, dict[str, str]] = {}
    for entry in sorted(tools_dir.iterdir(), key=lambda p: p.name):
        if not entry.is_dir() or entry.name.startswith((".", "__")):
            continue
        manifest = entry / "manifest.toml"
        adapter = entry / "adapter.py"
        if manifest.is_file() and adapter.is_file():
            adapters[entry.name] = {
                "manifest_sha256": _sha256_file(manifest),
                "adapter_sha256": _sha256_file(adapter),
            }
    return {"version": 1, "adapters": adapters}


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    payload = build_lock_payload()
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if "--check" in args:
        if not LOCK_PATH.is_file():
            print(f"Missing lockfile: {LOCK_PATH}", file=sys.stderr)
            return 1
        current = LOCK_PATH.read_text(encoding="utf-8")
        if current != rendered:
            print(
                f"{LOCK_PATH} is out of date. Run: .venv/bin/python scripts/update_bundle_lock.py",
                file=sys.stderr,
            )
            return 1
        return 0

    LOCK_PATH.write_text(rendered, encoding="utf-8")
    print(f"Wrote {LOCK_PATH} ({len(payload['adapters'])} adapters).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
