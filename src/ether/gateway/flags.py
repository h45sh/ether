"""Subprocess argument allowlisting and flag injection firewall (ether.gateway.flags)."""

from __future__ import annotations

import re
import shlex
from typing import Any, List, Optional, Sequence

from ether.gateway.gate import GatePolicy

SHELL_METACHAR_RE = re.compile(r"[|;&$`\n\r\x00]")
DEFAULT_DANGEROUS_FLAGS = frozenset(
    {"-oG", "-oN", "-oA", "--script", "--proxy", "-iL", "--config", "--eval"}
)


class FlagFirewallError(ValueError):
    """Raised when CLI arguments violate FlagFirewall security policy."""


class FlagFirewall:
    """Deep preflight firewall deriving strict argument AST rules from manifest.toml."""

    def __init__(self, registry: Optional[Any] = None) -> None:
        self._registry = registry

    def _get_manifest(self, tool_name: str) -> Optional[Any]:
        if self._registry is None:
            return None
        tool_data = self._registry.get_tool(tool_name)
        if isinstance(tool_data, dict):
            return tool_data.get("manifest")
        return None

    @staticmethod
    def _extract_flag_head(token: str, delimiters: Sequence[str]) -> str:
        """Extract the base flag name from compound tokens like --resolve=a:b or -uhttp://..."""
        for delim in delimiters:
            if delim in token and token.startswith("-"):
                return token.split(delim, 1)[0]
        # Handle joined short flag like -uhttp://... or -p80,443
        if len(token) > 2 and token.startswith("-") and not token.startswith("--"):
            if token[2:] and not token[2].isalpha():
                return token[:2]
            if token.startswith("-u") and ("http://" in token or "https://" in token):
                return "-u"
        return token

    @staticmethod
    def _extract_embedded_values(token: str, delimiters: Sequence[str]) -> List[str]:
        """Decompose compound flag values (delimited by =, :, ,) for target inspection."""
        values: List[str] = []
        if "=" in token and token.startswith("-"):
            rhs = token.split("=", 1)[1]
            for part in rhs.split(","):
                part = part.strip()
                if part:
                    values.append(part)
                    if ":" in part and "://" not in part:
                        for sub in part.split(":"):
                            if sub.strip():
                                values.append(sub.strip())
        elif (
            token.startswith("-u")
            and len(token) > 2
            and ("http://" in token or "https://" in token)
        ):
            values.append(token[2:])
        elif not token.startswith("-"):
            for delim in delimiters:
                if delim == "," and "," in token:
                    values.extend(p.strip() for p in token.split(",") if p.strip())
        return values

    def validate_arguments(
        self,
        tool_name: str,
        args: Sequence[str] | str,
        policy: GatePolicy,
    ) -> List[str]:
        """Validate and sanitize CLI arguments against manifest [flags] and GatePolicy."""
        if isinstance(args, str):
            try:
                tokens = shlex.split(args)
            except ValueError as e:
                raise FlagFirewallError(f"Malformed flag string for '{tool_name}': {e}") from e
        else:
            tokens = [str(a) for a in args]

        sanitized: List[str] = []
        for tok in tokens:
            if SHELL_METACHAR_RE.search(tok):
                raise FlagFirewallError(
                    f"Blocked shell metacharacter in argument '{tok}' for tool '{tool_name}'."
                )
            sanitized.append(tok)

        if policy == GatePolicy.UNRESTRICTED:
            return sanitized

        manifest = self._get_manifest(tool_name)
        flags_cfg = getattr(manifest, "flags", None) if manifest is not None else None
        allowed = set(getattr(flags_cfg, "allowed", []) or [])
        blocked = set(getattr(flags_cfg, "blocked", []) or [])
        delimiters = list(
            getattr(flags_cfg, "compound_delimiters", ["=", ":", ","]) or ["=", ":", ","]
        )

        effective_blocked = (DEFAULT_DANGEROUS_FLAGS - allowed) | blocked

        for tok in sanitized:
            if tok.startswith("-"):
                head = self._extract_flag_head(tok, delimiters)
                if head in effective_blocked or tok in effective_blocked:
                    raise FlagFirewallError(
                        f"Flag '{head}' is explicitly blocked for tool '{tool_name}' under SAFE policy."
                    )
                if allowed and head not in allowed and tok not in allowed:
                    raise FlagFirewallError(
                        f"Flag '{head}' is not in manifest [flags].allowed for '{tool_name}' under SAFE policy."
                    )

        return sanitized
