"""Pluggable adapter registry and manifest discovery."""

from ether.registry.adapter import ToolAdapter
from ether.registry.assets import (
    DEFAULT_WORDLIST_NAME,
    WORDLIST_MACRO_REGEX,
    AssetNotFoundError,
    resolve_wordlist,
    substitute_wordlist_macros,
)
from ether.registry.manifest import Manifest
from ether.registry.registry import ToolRegistry

__all__ = [
    "AssetNotFoundError",
    "DEFAULT_WORDLIST_NAME",
    "Manifest",
    "ToolAdapter",
    "ToolRegistry",
    "WORDLIST_MACRO_REGEX",
    "resolve_wordlist",
    "substitute_wordlist_macros",
]
