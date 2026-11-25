"""Validation and policy enforcement for tool actions."""

import ipaddress
import json
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from ether import paths
from ether.common.algorithms import IPRadixTrie
from ether.common.exceptions import EtherError
from ether.gateway.network import get_lhost_info
from ether.gateway.scope import (
    METADATA_HOSTNAMES,
    METADATA_IPS,
    EngagementScope,
    ScopeValidator,
)
from ether.graph.store import GraphStore
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


def is_blocked_destination(text: str) -> bool:
    """Check if a string contains known restricted destinations like cloud metadata,
    routing IP/hostname checks through ScopeValidator.
    """
    if not text:
        return False
    lower_text = text.lower()
    for blocked in BLOCKED_TARGETS:
        if blocked in lower_text:
            return True

    # Tokenize input to detect embedded IP/host candidates via ScopeValidator
    tokens = lower_text.replace("=", " ").replace("&", " ").replace(";", " ").split()
    metadata_scope = EngagementScope(allow_loopback=True)
    for raw_tok in tokens:
        tok = _strip_token_delimiters(raw_tok)
        if not tok:
            continue
        host = ScopeValidator.parse_host_candidate(tok)
        if ScopeValidator._parse_ip(host) is not None or host in METADATA_HOSTNAMES:
            verdict = ScopeValidator.is_in_scope(
                tok, metadata_scope, policy_is_unrestricted=False
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
    ):
        self.registry = registry
        self.store = store
        self.policy = policy
        self.scope = scope if scope is not None else EngagementScope()
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

        verifier = PreflightVerifier(registry=self.registry, policy=self.policy)
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
        from ether.core.session import ExecutionSession, SubprocessCommandRunner

        if not self.store:
            raise ValueError(
                "ActionGateway requires a configured GraphStore to spawn an ExecutionSession."
            )

        runner = command_runner or SubprocessCommandRunner(Executor())
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
            self._allowed_cidrs_trie = None
            self.scope.allowed_cidrs = []
        else:
            cleaned = [c.strip() for c in allowed_cidrs if c.strip()]
            self._allowed_cidrs = [ipaddress.ip_network(c, strict=False) for c in cleaned]
            self._allowed_cidrs_trie = IPRadixTrie()
            for net in self._allowed_cidrs:
                self._allowed_cidrs_trie.insert(net)
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
            if ScopeValidator._parse_ip(host) is not None:
                verdict = ScopeValidator.is_in_scope(
                    tok, cidr_scope, policy_is_unrestricted=False
                )
                if not verdict.allowed:
                    return False
        return True

    @staticmethod
    def infer_target_finding(target: str) -> BaseFinding:
        """Infer the typed BaseFinding entity from a raw target string."""
        import ipaddress

        from ether.schemas.base import BaseFinding
        from ether.schemas.dns import DomainInfo
        from ether.schemas.network import NetworkHost
        from ether.schemas.web import WebEndpoint

        try:
            ipaddress.ip_address(target)
            return NetworkHost.create(ip=target)
        except ValueError:
            pass

        if target.startswith("http://") or target.startswith("https://"):
            return WebEndpoint.create(url=target)

        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return BaseFinding(
                    schema_type="network.netblock", pik={"cidr": target}, data={"cidr": target}
                )
            except ValueError:
                pass

        return DomainInfo.create(domain=target)

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

        resolved["WORDLIST"] = paths.get_wordlist_path("common_dirs")
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
        # 1. Normalize flags -> raw_flags and enforce destination/scope if not UNRESTRICTED
        if action.params and "flags" in action.params and "raw_flags" not in action.params:
            action.params["raw_flags"] = action.params["flags"]
        raw_flags = action.params.get("raw_flags", "") if action.params else ""
        if self.policy != GatePolicy.UNRESTRICTED:
            if is_blocked_destination(raw_flags) or is_blocked_destination(action.tool_name):
                raise ActionValidationError(
                    "Access to cloud metadata endpoints is strictly prohibited."
                )
            if self._allowed_cidrs and not self.validate_target_scope(raw_flags):
                raise ActionValidationError(
                    "Target in command arguments violates authorized engagement CIDR scope."
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
