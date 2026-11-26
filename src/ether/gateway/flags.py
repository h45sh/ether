"""Subprocess argument allowlisting and flag injection firewall (ether.gateway.flags)."""

from __future__ import annotations

import ipaddress
import re
import shlex
import urllib.parse
from dataclasses import dataclass
from typing import Any, List, Literal, Optional, Sequence

from ether.gateway.gate import GatePolicy

SHELL_METACHAR_RE = re.compile(r"[|;&$`\n\r\x00]")
DEFAULT_DANGEROUS_FLAGS = frozenset(
    {"-oG", "-oN", "-oA", "--script", "--proxy", "-iL", "--config", "--eval"}
)


@dataclass(frozen=True)
class ParsedArgument:
    """Typed AST node representing a single parsed CLI argument token."""

    raw: str
    kind: Literal["flag", "flag_value", "positional"]
    head: str
    embedded_values: tuple[str, ...] = ()


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

    @staticmethod
    def _is_valid_positional_target(token: str) -> bool:
        """Return True if a standalone positional token is a well-formed IP, CIDR, URL, or host."""
        if not token or token.startswith("/") or token.startswith("file:"):
            return False
        try:
            ipaddress.ip_network(token, strict=False)
            return True
        except ValueError:
            pass
        if "://" in token:
            parsed = urllib.parse.urlparse(token)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        # Hostname, host:port, or numeric/octal/hex IP literal (canonicalized by ActionGateway/ScopeValidator)
        host_part = token.split(":", 1)[0]
        if re.match(r"^(?:0x[0-9a-fA-F]+|\d+)(?:\.(?:0x[0-9a-fA-F]+|\d+))*$", host_part):
            return True
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$", host_part))

    def parse_ast(self, tokens: Sequence[str], delimiters: Sequence[str]) -> List[ParsedArgument]:
        """Parse CLI tokens into a typed argument AST."""
        ast_nodes: List[ParsedArgument] = []
        expect_value = False
        for tok in tokens:
            embedded = tuple(self._extract_embedded_values(tok, delimiters))
            if tok.startswith("-"):
                head = self._extract_flag_head(tok, delimiters)
                ast_nodes.append(
                    ParsedArgument(raw=tok, kind="flag", head=head, embedded_values=embedded)
                )
                # Standalone flag without inline '=' may consume the next non-flag token as its value
                expect_value = "=" not in tok and head == tok
            elif expect_value:
                ast_nodes.append(
                    ParsedArgument(raw=tok, kind="flag_value", head=tok, embedded_values=embedded)
                )
                expect_value = False
            else:
                ast_nodes.append(
                    ParsedArgument(raw=tok, kind="positional", head=tok, embedded_values=embedded)
                )
        return ast_nodes

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
        raw_allowed = getattr(flags_cfg, "allowed", None) if flags_cfg is not None else None
        if isinstance(raw_allowed, (list, tuple, set, frozenset)):
            if flags_cfg is not None and hasattr(flags_cfg, "model_fields_set"):
                has_allowed_contract = "allowed" in flags_cfg.model_fields_set
            else:
                has_allowed_contract = True
            allowed = set(raw_allowed)
        else:
            has_allowed_contract = False
            allowed = set()
        raw_blocked = getattr(flags_cfg, "blocked", None) if flags_cfg is not None else None
        blocked = (
            set(raw_blocked) if isinstance(raw_blocked, (list, tuple, set, frozenset)) else set()
        )
        raw_delims = (
            getattr(flags_cfg, "compound_delimiters", None) if flags_cfg is not None else None
        )
        delimiters = (
            list(raw_delims)
            if isinstance(raw_delims, (list, tuple, set, frozenset)) and raw_delims
            else ["=", ":", ","]
        )

        effective_blocked = (DEFAULT_DANGEROUS_FLAGS - allowed) | blocked
        ast_nodes = self.parse_ast(sanitized, delimiters)

        for idx, node in enumerate(ast_nodes):
            for val in node.embedded_values:
                if SHELL_METACHAR_RE.search(val):
                    raise FlagFirewallError(
                        f"Blocked shell metacharacter in embedded value '{val}' for tool '{tool_name}'."
                    )

            if node.kind == "flag":
                if node.head in effective_blocked or node.raw in effective_blocked:
                    raise FlagFirewallError(
                        f"Flag '{node.head}' is explicitly blocked for tool '{tool_name}' under SAFE policy."
                    )
                if has_allowed_contract and node.head not in allowed and node.raw not in allowed:
                    raise FlagFirewallError(
                        f"Flag '{node.head}' is not in manifest [flags].allowed for '{tool_name}' under SAFE policy."
                    )
            elif node.kind == "positional":
                if idx == 0 and node.raw == tool_name:
                    continue
                if tool_name == "sudo":
                    continue
                if not self._is_valid_positional_target(node.raw):
                    raise FlagFirewallError(
                        f"Unvalidated positional argument '{node.raw}' rejected for '{tool_name}' under SAFE policy."
                    )

        return sanitized
