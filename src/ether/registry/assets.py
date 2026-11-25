"""Asset management and dynamic wordlist resolution seam for Ether.

Deep module encapsulating wordlist resolution across filesystem paths,
environment overrides, system directories (/usr/share/seclists), and
embedded emergency fallbacks.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ether import paths

# Embedded minimal fallback list
EMBEDDED_MINIMAL_WORDLIST = (
    Path(__file__).resolve().parent.parent / "assets" / "wordlists" / "minimal.txt"
)

COMMON_SYSTEM_WORDLIST_DIRS = [
    Path("/usr/share/seclists/Discovery/Web-Content"),
    Path("/usr/share/seclists"),
    Path("/usr/share/wordlists/dirb"),
    Path("/usr/share/wordlists/dirbuster"),
    Path("/usr/share/wordlists"),
]


class AssetNotFoundError(FileNotFoundError):
    """Raised when a requested security asset or wordlist cannot be resolved."""

    pass


def resolve_wordlist(spec: str, data_dir: Optional[str] = None) -> Path:
    """Resolve a wordlist specification to an absolute Path on disk.

    Resolution hierarchy:
    1. Direct filesystem path (if exists)
    2. $ETHER_WORDLISTS_DIR/<spec>
    3. User/session data dir (~/.ether/wordlists/<spec>)
    4. System wordlist search paths (/usr/share/seclists, /usr/share/wordlists)
    5. Embedded minimal fallback (if requested generic common list or minimal)
    6. Raise AssetNotFoundError with remediation hints.
    """
    if not spec or not spec.strip():
        if EMBEDDED_MINIMAL_WORDLIST.is_file():
            return EMBEDDED_MINIMAL_WORDLIST
        raise AssetNotFoundError("Empty wordlist specification provided.")

    clean = spec.strip()

    # Strip flag/macro prefixes like '-w @common.txt', '@common.txt', 'wordlist:common.txt'
    if clean.startswith("-w "):
        clean = clean[3:].strip()
    if clean.startswith("@"):
        clean = clean[1:].strip()
    if clean.startswith("wordlist:"):
        clean = clean[9:].strip()
    if clean.startswith("{wordlist") and clean.endswith("}"):
        inner = clean[9:-1].lstrip(":")
        clean = inner if inner else "common.txt"

    # Tier 1: Direct filesystem path
    candidate = Path(os.path.abspath(os.path.expanduser(clean)))
    if candidate.is_file():
        return candidate

    # Tier 2: ETHER_WORDLISTS_DIR environment variable
    env_dir = os.environ.get("ETHER_WORDLISTS_DIR")
    if env_dir:
        env_candidate = Path(env_dir) / clean
        if env_candidate.is_file():
            return env_candidate
        if not clean.endswith(".txt"):
            env_txt = Path(env_dir) / f"{clean}.txt"
            if env_txt.is_file():
                return env_txt

    # Tier 3: ~/.ether/wordlists
    user_wordlists_dir = Path(paths.get_default_wordlists_dir(data_dir))
    user_candidate = user_wordlists_dir / clean
    if user_candidate.is_file():
        return user_candidate
    if not clean.endswith(".txt"):
        user_txt = user_wordlists_dir / f"{clean}.txt"
        if user_txt.is_file():
            return user_txt

    # Tier 4: System paths (/usr/share/seclists, etc.)
    for sys_dir in COMMON_SYSTEM_WORDLIST_DIRS:
        if sys_dir.is_dir():
            sys_candidate = sys_dir / clean
            if sys_candidate.is_file():
                return sys_candidate
            if not clean.endswith(".txt"):
                sys_txt = sys_dir / f"{clean}.txt"
                if sys_txt.is_file():
                    return sys_txt
            try:
                for match in sys_dir.glob(f"**/{clean}"):
                    if match.is_file():
                        return match
            except Exception:
                pass

    # Tier 5: Embedded minimal fallback
    if EMBEDDED_MINIMAL_WORDLIST.is_file():
        return EMBEDDED_MINIMAL_WORDLIST

    raise AssetNotFoundError(
        f"Unable to resolve wordlist '{spec}'. "
        "Set ETHER_WORDLISTS_DIR or install SecLists at /usr/share/seclists."
    )
