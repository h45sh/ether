"""Asset management and dynamic wordlist resolution seam for Ether.

Deep module encapsulating wordlist resolution across filesystem paths,
environment overrides, system directories (/usr/share/seclists), macro
expansion, and embedded emergency fallbacks.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional, Tuple

from ether import paths

# Matches {wordlist} or {wordlist:name}
WORDLIST_MACRO_REGEX = re.compile(r"\{wordlist(?::([a-zA-Z0-9_\-]+))?\}")

DEFAULT_WORDLIST_NAME = "common_dirs"

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


def _find_in_directory(directory: Path, name: str, recursive: bool = False) -> Optional[Path]:
    """Locate `name` or `name.txt` inside `directory`, optionally recursing."""
    if not directory.is_dir():
        return None
    direct = directory / name
    if direct.is_file():
        return direct
    if not name.endswith(".txt"):
        with_ext = directory / f"{name}.txt"
        if with_ext.is_file():
            return with_ext
    if recursive:
        patterns = [f"**/{name}"]
        if not name.endswith(".txt"):
            patterns.append(f"**/{name}.txt")
        for pattern in patterns:
            try:
                for match in directory.glob(pattern):
                    if match.is_file():
                        return match
            except OSError:
                continue
    return None


def resolve_wordlist(
    spec: str,
    data_dir: Optional[str] = None,
    search_roots: Optional[List[Path]] = None,
    allow_fallback: bool = True,
) -> Path:
    """Resolve a wordlist specification or macro to an absolute Path on disk.

    Resolution hierarchy:
    1. Direct filesystem path (if exists)
    2. $ETHER_WORDLISTS_DIR/<spec>
    3. User/session data dir (~/.ether/wordlists/<spec>)
    4. Search roots (injectable `search_roots` or system SecLists/wordlists)
    5. Embedded minimal fallback (`minimal.txt`, when `allow_fallback=True`)
    6. Raise AssetNotFoundError with remediation hints.
    """
    if not spec or not spec.strip():
        if allow_fallback and EMBEDDED_MINIMAL_WORDLIST.is_file():
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

    macro_match = WORDLIST_MACRO_REGEX.fullmatch(clean)
    if macro_match:
        named_arg = macro_match.group(1)
        clean = named_arg if named_arg else DEFAULT_WORDLIST_NAME

    # Tier 1: Direct filesystem path
    candidate = Path(os.path.abspath(os.path.expanduser(clean)))
    if candidate.is_file():
        return candidate

    # Tier 2: ETHER_WORDLISTS_DIR environment variable
    env_dir = os.environ.get("ETHER_WORDLISTS_DIR")
    if env_dir:
        found = _find_in_directory(Path(env_dir), clean)
        if found is not None:
            return found

    # Tier 3: ~/.ether/wordlists (or injected data_dir/wordlists)
    user_wordlists_dir = Path(paths.get_default_wordlists_dir(data_dir))
    found = _find_in_directory(user_wordlists_dir, clean)
    if found is not None:
        return found

    # Tier 4: Search roots (injectable for hermetic testing or system SecLists/wordlists)
    roots = search_roots if search_roots is not None else COMMON_SYSTEM_WORDLIST_DIRS
    for sys_dir in roots:
        found = _find_in_directory(sys_dir, clean, recursive=True)
        if found is not None:
            return found

    # Tier 5: Embedded minimal fallback
    if allow_fallback and EMBEDDED_MINIMAL_WORDLIST.is_file():
        return EMBEDDED_MINIMAL_WORDLIST

    raise AssetNotFoundError(
        f"Unable to resolve wordlist '{spec}'. "
        "Set ETHER_WORDLISTS_DIR or install SecLists at /usr/share/seclists."
    )


def substitute_wordlist_macros(
    text: str,
    user_override: Optional[str] = None,
    data_dir: Optional[str] = None,
    search_roots: Optional[List[Path]] = None,
) -> Tuple[str, List[str]]:
    """Substitute {wordlist} and {wordlist:name} tokens in command/flag text.

    Args:
        text: Command or flag string containing macros.
        user_override: Optional user-supplied custom wordlist path overriding macros.
        data_dir: Optional Ether data directory for user wordlists.
        search_roots: Optional list of search root directories.

    Returns:
        Tuple of (substituted_text, list_of_resolved_file_paths).
    """
    resolved_paths: List[str] = []

    def _replace_macro(match: re.Match[str]) -> str:
        target_spec = user_override.strip() if user_override and user_override.strip() else match.group(0)
        resolved = str(
            resolve_wordlist(target_spec, data_dir=data_dir, search_roots=search_roots)
        )
        resolved_paths.append(resolved)
        return resolved

    result_text = WORDLIST_MACRO_REGEX.sub(_replace_macro, text)
    return result_text, resolved_paths
