"""Validation and policy enforcement for tool actions."""

import ipaddress
import json
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from ether.common.exceptions import EtherError
from ether.gateway.network import get_lhost_info
from ether.gateway.scope import (
    METADATA_HOSTNAMES,
    METADATA_IPS,
    EngagementScope,
    ScopeValidator,
)
from ether.graph.store import GraphStore
from ether.registry.assets import DEFAULT_WORDLIST_NAME, resolve_wordlist
from ether.registry.registry import ToolRegistry
from ether.schemas.base import BaseFinding
from ether.schemas.power import ActionRequest, ActionSource


def _resolve_lhost() -> Tuple[Optional[str], Optional[str]]:
    import sys

    pf = (
        sys.modules.get("cyguide.coordination.power_facade")
        or sys.modules.get("cyguide.engine.power_facade")
        or sys.modules.get("ether.facade")
    )
    resolver = getattr(pf, "get_lhost_info", get_lhost_info) if pf else get_lhost_info
    try:
        return resolver()
    except Exception:
        return None, None


BLOCKED_TARGETS = (
    METADATA_HOSTNAMES
    | METADATA_IPS
    | {
        "169.254.",  # IPv4 Link-Local / Cloud Metadata (AWS, Azure, GCP, DigitalOcean, Oracle)
        "2852039166",  # Decimal notation of 169.254.169.254
        "0xa9fea9fe",  # Hex notation of 169.254.169.254
    }
)


def _strip_token_delimiters(token: str) -> str:
    return token.strip("\"'`()<>,;{}[]")


def is_blocked_destination(text: str, allow_loopback: bool = True) -> bool:
    """Check if a string contains known restricted destinations like cloud metadata or loopback,
    routing IP/hostname checks through ScopeValidator.
    """
    if not text:
        return False
    lower_text = text.lower()
    for blocked in BLOCKED_TARGETS:
        if blocked in lower_text:
            return True

    # Tokenize input to detect embedded IP/host candidates via ScopeValidator
    tokens = (
        lower_text.replace("=", " ").replace("&", " ").replace(";", " ").replace(",", " ").split()
    )
    metadata_scope = EngagementScope(allow_loopback=allow_loopback)
    for raw_tok in tokens:
        tok = _strip_token_delimiters(raw_tok)
        if not tok:
            continue
        for pfx in ("-u", "-t", "-l", "--url", "--target", "--proxy", "--resolve"):
            if tok.startswith(pfx):
                tok = tok[len(pfx) :].lstrip("=:")
                break
        if (
            ":" in tok
            and not tok.startswith("http")
            and ScopeValidator.parse_ip(ScopeValidator.parse_host_candidate(tok)) is None
        ):
            sub_tokens = tok.split(":")
        else:
            sub_tokens = [tok]
        for sub_tok in sub_tokens:
            sub_tok = _strip_token_delimiters(sub_tok)
            if not sub_tok:
                continue
            host = ScopeValidator.parse_host_candidate(sub_tok)
            if not allow_loopback and (host == "localhost" or host.endswith(".localhost")):
                return True
            if (
                ScopeValidator.parse_ip(host) is not None
                or host in METADATA_HOSTNAMES
                or "nip.io" in host
                or "localtest.me" in host
            ):
                verdict = ScopeValidator.is_in_scope(
                    sub_tok, metadata_scope, policy_is_unrestricted=False
                )
                if not verdict.allowed:
                    return True

    return False


class GatePolicy(str, Enum):
    """Policy mode governing gateway enforcement."""

    SAFE = "safe"  # Strict: blocks metadata, enforces CIDR, user shell only
    UNRESTRICTED = (
        "unrestricted"  # Unrestricted: allows any destination, autonomous shell, raw execution
    )


class ActionValidationError(EtherError):
    """Raised when an ActionRequest fails validation."""

    pass


class ActionGateway:
    """The validation and policy layer for Power Mode.

    Ensures that any ActionRequest is legitimate, targets valid entities,
    and respects the tool's input contract before execution.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        store: Optional[GraphStore] = None,
        allowed_cidrs: Optional[List[str]] = None,
        policy: GatePolicy = GatePolicy.SAFE,
        scope: Optional[EngagementScope] = None,
        settings: Optional[Any] = None,
    ):
        self.registry = registry
        self.store = store
        self.settings = settings
        self.policy = policy
        if scope is not None:
            self.scope = scope
        elif settings is not None:
            gw_cfg = getattr(settings, "gateway", None)
            self.scope = EngagementScope(
                allow_loopback=getattr(gw_cfg, "allow_loopback", False),
                allow_metadata=getattr(gw_cfg, "allow_metadata", False),
                allow_link_local=getattr(gw_cfg, "allow_link_local", False),
            )
        else:
            self.scope = EngagementScope()
        self._allowed_cidrs: Optional[List[Any]] = None
        effective_cidrs = (
            allowed_cidrs if allowed_cidrs is not None else (self.scope.allowed_cidrs or None)
        )
        if effective_cidrs:
            self.set_allowed_cidrs(effective_cidrs)

    def preflight_verify(
        self,
        tool_name: str,
        target: str,
        flags: str = "",
    ):
        """Run preflight verification checks (binary availability, URL schemes, wordlists, and security gating)."""
        from ether.gateway.preflight import PreflightVerifier

        verifier = PreflightVerifier(
            registry=self.registry,
            policy=self.policy,
            scope=self.scope,
        )
        return verifier.verify(tool_name=tool_name, target=target, flags=flags)

    async def _resolve_entity_target_str(self, action: ActionRequest) -> str:
        """Resolve an ActionRequest's target_entity_id to its underlying target string."""
        if not action.target_entity_id:
            return ""
        if self.store:
            node = await self.store.get_node(str(action.session_id), action.target_entity_id)
            if node:
                pik = node.get("pik")
                if not isinstance(pik, dict):
                    pik_json = node.get("pik_json", "")
                    if pik_json:
                        try:
                            pik = json.loads(pik_json)
                        except (TypeError, ValueError):
                            pik = {}
                if isinstance(pik, dict):
                    resolved = (
                        pik.get("url")
                        or pik.get("ip")
                        or pik.get("host_ip")
                        or pik.get("domain")
                        or pik.get("cidr")
                        or pik.get("target")
                    )
                    if resolved:
                        return str(resolved)
        return str(action.target_entity_id)

    async def verify_action(self, action: ActionRequest):
        """Validate an action request returning a structured PreflightReport rather than raising exceptions."""
        from ether.gateway.preflight import PreflightIssue

        raw_flags = ""
        if action.params:
            raw_flags = action.params.get("raw_flags") or action.params.get("flags", "")
        target_str = await self._resolve_entity_target_str(action)
        report = self.preflight_verify(
            tool_name=action.tool_name,
            target=target_str,
            flags=raw_flags,
        )

        try:
            await self.validate_action(action)
        except ActionValidationError as e:
            report.issues.append(
                PreflightIssue(
                    category="security",
                    severity="error",
                    title="Action validation error",
                    description=str(e),
                    remediation_hint="Ensure target and parameters comply with policy and CIDR scope.",
                )
            )

        return report

    if TYPE_CHECKING:
        from ether.core.session import CommandRunner

    def create_session(
        self,
        command_runner: Optional["CommandRunner"] = None,
        user_env: Optional[Dict[str, str]] = None,
        user_shell: Optional[str] = None,
    ):
        """Factory creating an ExecutionSession governed by this ActionGateway and its configured policies."""
        from ether.core.executor import Executor
        from ether.core.session import ExecutionSession

        if not self.store:
            raise ValueError(
                "ActionGateway requires a configured GraphStore to spawn an ExecutionSession."
            )

        runner = command_runner or Executor()
        return ExecutionSession(
            store=self.store,
            gateway=self,
            registry=self.registry,
            command_runner=runner,
            user_env=user_env,
            user_shell=user_shell,
        )

    def set_allowed_cidrs(self, allowed_cidrs: Optional[List[str]]) -> None:
        """Configure declarative CIDR scope boundaries for engagements."""
        if not allowed_cidrs:
            self._allowed_cidrs = None
            self.scope.allowed_cidrs = []
        else:
            cleaned = [c.strip() for c in allowed_cidrs if c.strip()]
            self._allowed_cidrs = [ipaddress.ip_network(c, strict=False) for c in cleaned]
            self.scope.allowed_cidrs = cleaned

    def validate_target_scope(self, text_or_ip: str) -> bool:
        """Ensure any target IPs in text belong to the authorized engagement CIDR scope via ScopeValidator.

        Returns True if within scope (or if no scope restrictions are configured).
        """
        if not self._allowed_cidrs or not text_or_ip:
            return True

        cidr_scope = EngagementScope(
            allowed_cidrs=list(self.scope.allowed_cidrs),
            allowed_domains=list(self.scope.allowed_domains),
            allow_loopback=True,
            allow_metadata=True,
            allow_link_local=True,
        )
        tokens = text_or_ip.replace("=", " ").replace("&", " ").replace(";", " ").split()
        for raw_tok in tokens:
            tok = _strip_token_delimiters(raw_tok)
            if not tok:
                continue
            host = ScopeValidator.parse_host_candidate(tok)
            if ScopeValidator.parse_ip(host) is not None:
                verdict = ScopeValidator.is_in_scope(tok, cidr_scope, policy_is_unrestricted=False)
                if not verdict.allowed:
                    return False
        return True

    @staticmethod
    def infer_target_finding(target: str) -> BaseFinding:
        """Infer the typed BaseFinding entity from a raw target string."""
        from ether.registry.target_inference import infer_target_finding

        return infer_target_finding(target)

    @staticmethod
    def resolve_entity_variables(
        pik: Optional[Dict[str, Any]] = None,
        lhost_resolver: Optional[Callable[[], Tuple[Optional[str], Optional[str]]]] = None,
    ) -> Dict[str, Any]:
        """Extract standard investigation variables ($TARGET, $PORT, $SERVICE, $PROTOCOL, $LHOST, $IFACE)."""
        resolved: Dict[str, Any] = {}
        if pik:
            target = pik.get("ip") or pik.get("domain") or pik.get("host_ip")
            if target:
                resolved["TARGET"] = target
            if "port" in pik:
                resolved["PORT"] = pik["port"]
            if "service" in pik:
                resolved["SERVICE"] = pik["service"]
            if "protocol" in pik:
                resolved["PROTOCOL"] = pik["protocol"]

        resolver = lhost_resolver or _resolve_lhost
        try:
            ip, iface = resolver()
            if ip:
                resolved["LHOST"] = ip
            if iface:
                resolved["IFACE"] = iface
        except Exception:
            pass

        resolved["WORDLIST"] = str(resolve_wordlist(DEFAULT_WORDLIST_NAME))
        return resolved

    @staticmethod
    def interpolate_variables(text: str, variables: Dict[str, Any]) -> str:
        """Replace $VAR placeholders in command text with resolved values."""
        for var_name, val in variables.items():
            placeholder = f"${var_name}"
            if placeholder in text:
                text = text.replace(placeholder, str(val))
        return text

    async def validate_action(self, action: ActionRequest) -> bool:
        """Validate an action request against registry and store state.

        Raises:
            ActionValidationError: If validation fails.
        """
        # 1. Normalize flags -> raw_flags and enforce metacharacter + destination/scope checks
        if action.params and "flags" in action.params and "raw_flags" not in action.params:
            action.params["raw_flags"] = action.params["flags"]
        raw_flags = action.params.get("raw_flags", "") if action.params else ""
        if isinstance(raw_flags, list):
            raw_flags = " ".join(str(f) for f in raw_flags)
        if raw_flags:
            from ether.gateway.flags import FlagFirewall, FlagFirewallError

            firewall = FlagFirewall(registry=self.registry)
            try:
                firewall.validate_arguments(action.tool_name, raw_flags, self.policy)
            except FlagFirewallError as fw_err:
                raise ActionValidationError(str(fw_err)) from fw_err
        if self.policy != GatePolicy.UNRESTRICTED:
            allow_loopback = (
                getattr(self.scope, "allow_loopback", False)
                if hasattr(self, "scope") and self.scope
                else False
            )
            if is_blocked_destination(
                raw_flags, allow_loopback=allow_loopback
            ) or is_blocked_destination(action.tool_name, allow_loopback=allow_loopback):
                raise ActionValidationError(
                    "Access to cloud metadata endpoints is strictly prohibited (or unauthorized loopback destination)."
                )
            if self._allowed_cidrs and not self.validate_target_scope(raw_flags):
                raise ActionValidationError(
                    "Target in command arguments violates authorized engagement CIDR scope."
                )
            # Async DNS resolution check for hostname/URL tokens in raw_flags under SAFE policy
            if raw_flags:
                for raw_tok in raw_flags.replace("=", " ").split():
                    tok = _strip_token_delimiters(raw_tok)
                    if not tok or tok.startswith("-"):
                        continue
                    host = ScopeValidator.parse_host_candidate(tok)
                    if (
                        host
                        and ("." in host or "://" in tok)
                        and ScopeValidator.parse_ip(host) is None
                    ):
                        verdict = await ScopeValidator.check_destination(
                            tok, scope=self.scope, policy_is_unrestricted=False
                        )
                        if not verdict.allowed:
                            raise ActionValidationError(
                                f"Destination '{tok}' blocked by scope/DNS policy ({verdict.reason})."
                            )

        # 2. Resolve Tool
        tool_data = self.registry.get_tool(action.tool_name)

        # 3. Policy: Handle Shell Commands
        if not tool_data:
            # Only allow arbitrary shell commands if explicitly requested (!) and by a user
            if action.is_explicit_shell and action.triggered_by == ActionSource.USER:
                return True

            # If not explicit or not user, reject
            reason = "is not a registered tool"
            if not action.is_explicit_shell:
                reason += " and no explicit shell prefix ('!') was provided"

            raise ActionValidationError(f"Action '{action.tool_name}' {reason}.")

        # 4. Standard Validation for Registered Tools
        manifest = tool_data["manifest"]

        # 5. Check if target entity exists and is compatible
        # POLICY: For manual USER actions, we allow execution without a selected entity
        # as they might be providing the target in the raw_flags (e.g., 'nmap 1.1.1.1')
        if not action.target_entity_id:
            if action.triggered_by == ActionSource.USER:
                return True
            raise ActionValidationError(
                f"Tool '{action.tool_name}' requires a selected target entity."
            )

        if not self.store:
            return True
        node = await self.store.get_node(str(action.session_id), action.target_entity_id)
        if not node:
            raise ActionValidationError(
                f"Target entity '{action.target_entity_id}' not found in session '{action.session_id}'."
            )

        # Enforce destination safety on the target entity (respecting GatePolicy.UNRESTRICTED)
        if self.policy != GatePolicy.UNRESTRICTED:
            pik_str = node.get("pik_json", "")
            if is_blocked_destination(pik_str):
                raise ActionValidationError(
                    "Target entity points to a prohibited cloud metadata endpoint."
                )

            if self._allowed_cidrs and not self.validate_target_scope(pik_str):
                raise ActionValidationError(
                    "Target entity IP violates authorized engagement CIDR scope."
                )

        target_schema = node["schema_type"]
        accepted_inputs = manifest.input.get("accepts", []) if manifest else []
        if accepted_inputs and target_schema not in accepted_inputs:
            raise ActionValidationError(
                f"Tool '{action.tool_name}' does not accept input type '{target_schema}'. "
                f"Accepted types: {', '.join(accepted_inputs)}"
            )

        return True
