"""Pre-flight dependency, asset, capability, and parameter verification for Ether."""

from __future__ import annotations

import os
import re
import shutil
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional, Set, Tuple

from ether import paths
from ether.gateway.gate import GatePolicy
from ether.gateway.scope import EngagementScope, ScopeValidator
from ether.registry.wordlists import (
    DEFAULT_WORDLIST_NAME,
    WORDLIST_MACRO_REGEX,
    seed_bundled_wordlists,
)

WORDLIST_FLAG_REGEX = re.compile(
    r"(?:^|\s)(?:-w|--wordlist)(?:=|\s+)(\S+)",
    re.IGNORECASE,
)

INSTALLATION_HINTS: dict[str, str] = {
    "nmap": "sudo apt install nmap  (or: brew install nmap)",
    "gobuster": "sudo apt install gobuster  (or: go install github.com/OJ/gobuster/v3@v3.6.0)",
    "nikto": "sudo apt install nikto  (or: brew install nikto)",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6",
    "whois": "sudo apt install whois  (or: brew install whois)",
    "dnspython": "pip install dnspython",
    "ffuf": "go install github.com/ffuf/ffuf/v2@latest  (or: sudo apt install ffuf)",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "sqlmap": "sudo apt install sqlmap  (or: pip install sqlmap)",
    "netexec": "pipx install netexec  (or: pip install netexec)",
    "searchsploit": "sudo apt install exploitdb  (or: git clone https://gitlab.com/exploit-database/exploitdb.git)",
}

def get_tool_target_guidance(tool_name: str) -> str:
    """Return formatted Markdown target guidance dynamically generated for a specified security tool."""
    tool_lower = tool_name.lower()

    # Retrieve tool metadata and protocol theory if available in registry
    theory = ""
    description = ""
    reg = None
    try:
        from ether.registry.registry import ToolRegistry

        reg = ToolRegistry()
        reg.load_tools()
        t = reg.get_tool(tool_lower)
        if t and t.get("manifest"):
            m = t["manifest"]
            tool_meta = getattr(m, "meta", None)
            if tool_meta:
                description = getattr(tool_meta, "description", "")
                theory = getattr(tool_meta, "theory", "")
    except Exception:
        pass

    # Determine capabilities & target profile dynamically using the loaded registry
    verifier = PreflightVerifier(registry=reg)
    target_types = verifier._get_tool_target_types(tool_lower)

    if "url" in target_types and not any(t in target_types for t in ("ip", "cidr")):
        expected_format = "Complete HTTP or HTTPS URL (https://scanme.nmap.org, http://10.10.10.10:8080)"
        safe_sandbox = "http://scanme.nmap.org (or http://127.0.0.1:8080 with allow_loopback=True)"
        permissible = [
            "Official sandbox testbeds (scanme.nmap.org, testphp.vulnweb.com).",
            "Local loopback web servers (http://127.0.0.1, http://localhost:8000) when EngagementScope(allow_loopback=True) or --policy unrestricted is enabled.",
            "Authorized client web applications during penetration tests within defined Rules of Engagement.",
        ]
        prohibited = [
            "Cloud metadata URIs (http://169.254.169.254/latest/meta-data/, fd00:ec2::254).",
            "Third-party websites, production e-commerce platforms, or SaaS portals without explicit scope inclusion.",
            "Form endpoints that trigger emails, database writes, or financial transactions without authorization.",
        ]
        precautions = [
            "High concurrency can overwhelm low-spec web servers, exhausting worker pools and causing HTTP 503.",
            "Brute-forcing on applications with automatic WAF or anti-bot systems will trigger IP bans.",
            "Ensure rate limits are enforced to respect target infrastructure bandwidth.",
        ]
    elif "domain" in target_types and "ip" not in target_types:
        expected_format = "Base root domain name without protocol or path (example.com, nmap.org)"
        safe_sandbox = "example.com (IANA reserved domain) or your own registered domain assets"
        permissible = [
            "example.com for verifying DNS resolution and parsing pipelines.",
            "Client domains explicitly in scope for reconnaissance during authorized pentest engagements.",
            "Bug bounty programs that permit passive reconnaissance within scope.",
        ]
        prohibited = [
            "Internal network names (e.g. .local, .internal, .lan) which have no public DNS presence.",
            "URLs with protocols (http://) or paths (/api) — domain tools strictly expect a clean domain name.",
            "IP addresses (domain tools resolve records for domain names, not IP addresses).",
        ]
        precautions = [
            "Respect public API rate limits when querying upstream data sources to avoid IP throttling.",
            "Be aware of DNS caching: queries might return cached intermediate results from upstream resolvers.",
            "Zone Transfers (AXFR) will be logged on authoritative nameservers and can leak internal namespaces.",
        ]
    elif tool_lower in {"searchsploit"}:
        expected_format = "Software name and version string (Apache 2.4.49, OpenSSH 7.2p2) or CVE ID (2021-41773). Do NOT use URLs or IPs."
        safe_sandbox = "Apache 2.4.49 (famous CVE-2021-41773 RCE), ProFTPD 1.3.5, vsftpd 2.3.4"
        permissible = [
            "Searching for known public exploits, PoC scripts, and papers from local vulnerability archives.",
            "Filtering by title, CVE identifier, platform (Linux/Windows), or remote exploit type.",
            "Offline query analysis with zero network footprint.",
        ]
        prohibited = [
            "NEVER compile or execute downloaded public exploit code against live systems without auditing source code first!",
            "Do not enter raw IP addresses or URLs as search terms; searchsploit searches text descriptions.",
        ]
        precautions = [
            "Public exploits often require manual modification (offsets, shellcode, return addresses) to function.",
            "Always perform code review before running third-party exploit code.",
            "Keep the local exploit database updated using searchsploit -u.",
        ]
    elif tool_lower in {"netexec", "nxc"}:
        expected_format = "Target IPv4 (10.10.10.10), CIDR subnet (192.168.1.0/24), or NetBIOS/FQDN hostname (dc01.corp.local)"
        safe_sandbox = "Dedicated Active Directory lab ranges (e.g., GOAD, HackTheBox) or 127.0.0.1 with allow_loopback=True"
        permissible = [
            "Isolated Active Directory lab environments configured specifically for pentesting education.",
            "Local machine (127.0.0.1) when EngagementScope(allow_loopback=True) or --policy unrestricted is enabled.",
            "Authorized enterprise client subnets during approved engagement windows.",
        ]
        prohibited = [
            "Production Active Directory Domain Controllers during business hours without explicit change approval.",
            "Internet-facing public SMB (port 445) endpoints not owned by you.",
            "Cloud metadata endpoints.",
        ]
        precautions = [
            "Can trigger Active Directory account lockouts if password spraying against domains with lockout policies.",
            "SMB credential checks generate event ID 4625 and 4624 on the Domain Controller security event log.",
            "Sequential RPC queries can alert SIEM rules detecting credential access.",
        ]
    else:
        expected_format = "IPv4 (10.10.10.10), IPv6 (2001:db8::1), CIDR (192.168.1.0/24), IP Range (10.0.0.1-50), or Hostname (scanme.nmap.org)"
        safe_sandbox = "scanme.nmap.org (authorized test server) or 127.0.0.1 with allow_loopback=True"
        permissible = [
            "Official project sandbox (scanme.nmap.org) for testing version and script scans.",
            "Local loopback (127.0.0.1, localhost) when EngagementScope(allow_loopback=True) or --policy unrestricted is enabled.",
            "Private lab subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and container bridge networks with explicit authorization.",
        ]
        prohibited = [
            "Cloud metadata endpoints (169.254.169.254, 169.254.169.250, fd00:ec2::254) — potential SSRF vulnerability.",
            "Third-party production infrastructure, government, banking, or military IP ranges without written Rules of Engagement.",
            "Broadcast or multicast addresses (e.g. 255.255.255.255, 224.0.0.1) which can cause network amplification storms.",
        ]
        precautions = [
            "Aggressive timing templates and full port sweeps can saturate network firewalls, exhaust state tables, or crash fragile hardware.",
            "SYN half-open scans require raw socket capabilities (root/sudo privileges).",
            "UDP scanning is subject to OS-level ICMP rate limits (RFC 1812); expect scans to run slower.",
        ]

    mechanics = (
        theory.strip()
        or description.strip()
        or f"Automated security tool adapter for {tool_name}."
    )

    perm_bullets = "\n".join(f"- {p}" for p in permissible)
    proh_bullets = "\n".join(f"- {p}" for p in prohibited)
    prec_bullets = "\n".join(f"- {p}" for p in precautions)

    return (
        f"# Target Scope & Safety Guidance: {tool_name.upper()}\n\n"
        f"**Expected Format:** `{expected_format}`\n\n"
        f"**Safe Sandbox Target:** `{safe_sandbox}`\n\n"
        f"## Permissible & Effective Targets\n{perm_bullets}\n\n"
        f"## Strictly Prohibited & Dangerous Targets\n{proh_bullets}\n\n"
        f"## Operational Precautions & Ethics\n{prec_bullets}\n\n"
        f"## Protocol Mechanics & Behavior\n{mechanics}\n"
    )


@dataclass
class PreflightIssue:
    """An individual issue or recommendation identified during preflight checks."""

    category: Literal["binary", "wordlist", "target", "security"]
    severity: Literal["error", "warning", "info"]
    title: str
    description: str
    remediation_hint: str
    can_auto_remedy: bool = False
    remedy_label: Optional[str] = None
    remedy_action: Optional[str] = None
    remedy_payload: Optional[str] = None


@dataclass
class PreflightReport:
    """Consolidated outcome of preflight verification for a proposed command."""

    tool_name: str
    target: str
    flags: str
    issues: List[PreflightIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """True if there are zero blocking errors."""
        return not any(i.severity == "error" for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        """True if there are non-blocking warnings."""
        return any(i.severity == "warning" for i in self.issues)

    @property
    def errors(self) -> List[PreflightIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> List[PreflightIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def remediable_issues(self) -> List[PreflightIssue]:
        return [i for i in self.issues if i.can_auto_remedy]


class PreflightVerifier:
    """Deep module verifying tool dependencies, wordlist assets, target parameters,

    and security boundaries prior to subprocess dispatch.
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        wordlists_dir: Optional[str] = None,
        policy: GatePolicy = GatePolicy.SAFE,
        scope: Optional[EngagementScope] = None,
    ):
        self.registry = registry
        self.wordlists_dir = wordlists_dir
        self.policy = policy
        self.scope = scope if scope is not None else EngagementScope()

    def verify(
        self,
        tool_name: str,
        target: str,
        flags: str = "",
        recipe_idx: Optional[int] = None,
    ) -> PreflightReport:
        """Run comprehensive preflight verification and return a structured report."""
        clean_tool = (tool_name or "").strip().lower()
        clean_target = (target or "").strip()
        clean_flags = (flags or "").strip()

        report = PreflightReport(
            tool_name=clean_tool,
            target=clean_target,
            flags=clean_flags,
            issues=[],
        )

        if not clean_tool:
            report.issues.append(
                PreflightIssue(
                    category="binary",
                    severity="error",
                    title="No security tool selected",
                    description="An active security tool must be selected before executing scans.",
                    remediation_hint="Select a tool from the catalog or registry.",
                )
            )
            return report

        # 1. Binary Availability Check
        self._check_binary(clean_tool, report)

        # 2. Security Gating (Sudo & SSRF)
        self._check_security(clean_tool, clean_target, clean_flags, report)

        # 3. Target Variable & Scheme Validation
        self._check_target(clean_tool, clean_target, report)

        # 4. Wordlist Assets Validation
        self._check_wordlists(clean_tool, clean_flags, report)

        return report

    @staticmethod
    def quick_check(
        tool_name: str,
        target: str,
        flags: str = "",
        policy: GatePolicy = GatePolicy.SAFE,
        registry: Optional[Any] = None,
        scope: Optional[EngagementScope] = None,
    ) -> Optional[str]:
        """Perform a fast, non-blocking check returning a single concise warning string if any issue exists."""
        clean_target = (target or "").strip()
        clean_flags = (flags or "").strip()
        clean_tool = (tool_name or "").strip().lower()
        active_scope = scope if scope is not None else EngagementScope()

        if policy == GatePolicy.SAFE:
            if re.search(r"\bsudo\b", clean_flags) or re.search(r"\bsudo\b", clean_target):
                return "[!] Sudo execution is prohibited under Safe GatePolicy."

            if clean_target:
                verdict = ScopeValidator.is_in_scope(
                    clean_target, active_scope, policy_is_unrestricted=False
                )
                if not verdict.allowed:
                    if verdict.reason == "BLOCKED_LOOPBACK_UNAUTHORIZED":
                        return "[!] Loopback target is blocked under Safe GatePolicy unless allow_loopback=True."
                    return "[!] Target is blocked by cloud metadata or scope policy."

        if not clean_target:
            return "[!] Target address or host is required."

        if any(var in clean_target for var in ("$TARGET", "{target}", "{url}", "$PORT")):
            return "[!] Target contains unexpanded variable placeholder."

        if registry and clean_tool:
            target_types = PreflightVerifier(
                registry=registry, policy=policy, scope=active_scope
            )._get_tool_target_types(clean_tool)
            is_web = "url" in target_types and not any(t in target_types for t in ("ip", "cidr"))
            is_network = (
                "ip" in target_types or "cidr" in target_types
            ) and "url" not in target_types
            if is_web and not (
                clean_target.startswith("http://") or clean_target.startswith("https://")
            ):
                return f"[!] Web tool '{clean_tool}' expects 'http://' or 'https://' prefix."
            if is_network and (
                clean_target.startswith("http://") or clean_target.startswith("https://")
            ):
                return f"[!] Network tool '{clean_tool}' expects bare IP or hostname, not URL."

        return None

    def apply_remedy(
        self,
        issue: PreflightIssue,
        target: str,
        flags: str = "",
    ) -> Tuple[str, str, Optional[str]]:
        """Apply an automated one-click remediation to an identified preflight issue.

        Returns:
            Tuple of (updated_target, updated_flags, feedback_message)
        """
        action = issue.remedy_action
        payload = issue.remedy_payload

        if action == "seed_wordlists":
            dest_dir = self.wordlists_dir or paths.get_default_wordlists_dir()
            extracted = seed_bundled_wordlists(dest_dir)
            msg = f"Extracted {len(extracted)} starter wordlists to {dest_dir}."
            return target, flags, msg

        elif action == "fix_target_scheme":
            new_target = payload if payload else f"http://{target.strip()}"
            return new_target, flags, f"Updated target to: {new_target}"

        elif action == "strip_url_scheme":
            new_target = payload if payload else self._extract_clean_hostname(target)
            return new_target, flags, f"Stripped URL scheme: {new_target}"

        elif action == "set_default_target":
            new_target = payload or "scanme.nmap.org"
            return new_target, flags, f"Set target to test address: {new_target}"

        elif action == "remove_sudo":
            new_flags = re.sub(r"\bsudo\s*", "", flags).strip()
            return target, new_flags, "Removed 'sudo' from command parameters."

        elif action == "copy_install_command":
            return target, flags, payload or issue.remediation_hint

        return target, flags, None

    # --- Internal Verification Rules ---

    def _check_binary(self, tool_name: str, report: PreflightReport) -> None:
        """Verify that the tool's binary or coroutine dependency is installed and discoverable."""
        adapter = None
        manifest = None
        if self.registry:
            tool_data = self.registry.get_tool(tool_name)
            if tool_data:
                adapter = tool_data.get("adapter")
                manifest = tool_data.get("manifest")

        # Check for native coroutine tier
        is_coroutine = (
            manifest
            and getattr(getattr(manifest, "meta", None), "execution_tier", None) == "coroutine"
        ) or (adapter and getattr(adapter, "execution_tier", None) == "coroutine")

        if is_coroutine or tool_name in ("dnspython", "http_probe"):
            if adapter and hasattr(adapter, "validate_install"):
                try:
                    if not adapter.validate_install():
                        report.issues.append(
                            PreflightIssue(
                                category="binary",
                                severity="error",
                                title=f"Tool dependency for '{tool_name}' is not installed",
                                description=f"Required Python libraries for '{tool_name}' are not importable.",
                                remediation_hint=INSTALLATION_HINTS.get(
                                    tool_name, f"pip install {tool_name}"
                                ),
                            )
                        )
                except Exception:
                    pass
            return

        is_installed = False
        binary_name = tool_name
        if manifest and hasattr(manifest, "meta") and getattr(manifest.meta, "binary", None):
            binary_name = manifest.meta.binary
        elif adapter and hasattr(adapter, "binary"):
            binary_name = adapter.binary

        if adapter and hasattr(adapter, "validate_install"):
            try:
                is_installed = bool(adapter.validate_install())
            except Exception:
                is_installed = False
        else:
            is_installed = bool(shutil.which(binary_name))

        if not is_installed:
            hint = (
                INSTALLATION_HINTS.get(tool_name)
                or INSTALLATION_HINTS.get(binary_name)
                or f"sudo apt install {binary_name}"
            )
            report.issues.append(
                PreflightIssue(
                    category="binary",
                    severity="error",
                    title=f"Tool binary '{binary_name}' is not installed",
                    description=f"The executable '{binary_name}' was not found in system PATH.",
                    remediation_hint=hint,
                    can_auto_remedy=True,
                    remedy_label="Copy Install Command",
                    remedy_action="copy_install_command",
                    remedy_payload=hint,
                )
            )

    def _check_security(
        self,
        tool_name: str,
        target: str,
        flags: str,
        report: PreflightReport,
    ) -> None:
        """Enforce sandbox security restrictions (sudo ban, SSRF link-local gating under SAFE policy)."""
        if self.policy == GatePolicy.SAFE:
            # Sudo ban in Safe Policy
            if re.search(r"\bsudo\b", flags) or re.search(r"\bsudo\b", target):
                report.issues.append(
                    PreflightIssue(
                        category="security",
                        severity="error",
                        title="Privilege escalation ('sudo') is prohibited",
                        description="Commands cannot be executed with elevated root privileges under Safe GatePolicy.",
                        remediation_hint="Remove 'sudo' from command parameters.",
                        can_auto_remedy=True,
                        remedy_label="Remove sudo",
                        remedy_action="remove_sudo",
                        remedy_payload=re.sub(r"\bsudo\s*", "", flags).strip(),
                    )
                )

            # Unified ScopeValidator SSRF / Loopback / Scope Protection
            if target:
                verdict = ScopeValidator.is_in_scope(
                    target, self.scope, policy_is_unrestricted=False
                )
                if not verdict.allowed:
                    if verdict.reason == "BLOCKED_LOOPBACK_UNAUTHORIZED":
                        report.issues.append(
                            PreflightIssue(
                                category="security",
                                severity="error",
                                title=f"Target '{target}' is blocked by loopback policy",
                                description="Loopback addresses (127.0.0.0/8, ::1) are blocked under SAFE policy unless EngagementScope(allow_loopback=True) is set.",
                                remediation_hint="Enable allow_loopback=True in EngagementScope or use an authorized target (scanme.nmap.org).",
                                can_auto_remedy=True,
                                remedy_label="Set scanme.nmap.org",
                                remedy_action="set_default_target",
                                remedy_payload="scanme.nmap.org",
                            )
                        )
                    else:
                        report.issues.append(
                            PreflightIssue(
                                category="security",
                                severity="error",
                                title=f"Target '{target}' is blocked by security policy",
                                description=f"Target destination rejected by ScopeValidator ({verdict.reason}).",
                                remediation_hint="Choose a valid authorized target (e.g. scanme.nmap.org).",
                                can_auto_remedy=True,
                                remedy_label="Set scanme.nmap.org",
                                remedy_action="set_default_target",
                                remedy_payload="scanme.nmap.org",
                            )
                        )

    def _get_tool_target_types(self, tool_name: str) -> Set[str]:
        """Dynamically extract supported target types ('url', 'ip', 'cidr', 'domain') from ToolRegistry."""
        if self.registry:
            tool_data = self.registry.get_tool(tool_name)
            if tool_data and isinstance(tool_data, dict):
                manifest = tool_data.get("manifest")
                if manifest:
                    input_cfg = getattr(manifest, "input", {})
                    if isinstance(input_cfg, dict) and "target_types" in input_cfg:
                        return set(input_cfg["target_types"])
                    if hasattr(manifest, "target_types") and manifest.target_types:
                        return set(manifest.target_types)

                    accepts = (
                        input_cfg.get("accepts", [])
                        if isinstance(input_cfg, dict)
                        else getattr(input_cfg, "accepts", [])
                    )
                    types: Set[str] = set()
                    for schema in accepts:
                        if schema in ("web.endpoint", "web.url"):
                            types.add("url")
                        elif schema in ("network.host", "network.service"):
                            types.update({"ip", "cidr", "domain"})
                        elif schema in ("domain.info", "dns.record"):
                            types.update({"domain", "ip"})
                    if types:
                        return types

        return {"url", "ip", "cidr", "domain"}

    def _check_target(
        self,
        tool_name: str,
        target: str,
        report: PreflightReport,
    ) -> None:
        """Validate target presence, unresolved variable placeholders, and tool scheme alignment."""
        target_types = self._get_tool_target_types(tool_name)
        is_web = "url" in target_types and not any(t in target_types for t in ("ip", "cidr"))
        is_network_or_domain = (
            ("ip" in target_types or "domain" in target_types) and "url" not in target_types
        )
        if is_web:
            default_target = (
                "http://127.0.0.1:8888" if self.scope.allow_loopback else "http://scanme.nmap.org"
            )
        elif "domain" in target_types and "ip" not in target_types:
            default_target = "example.com"
        else:
            default_target = "127.0.0.1" if self.scope.allow_loopback else "scanme.nmap.org"

        if not target:
            report.issues.append(
                PreflightIssue(
                    category="target",
                    severity="error",
                    title="Target address or host is missing",
                    description="Security tools require an active target IP, domain, or URL to execute.",
                    remediation_hint=f"Provide a target or use local sandbox target '{default_target}'.",
                    can_auto_remedy=True,
                    remedy_label=f"Set '{default_target}'",
                    remedy_action="set_default_target",
                    remedy_payload=default_target,
                )
            )
            return

        # Check for unexpanded placeholder variables
        unexpanded = [
            var for var in ("$TARGET", "{target}", "{url}", "$PORT", "{domain}") if var in target
        ]
        if unexpanded:
            report.issues.append(
                PreflightIssue(
                    category="target",
                    severity="error",
                    title=f"Unexpanded variable placeholder: '{unexpanded[0]}'",
                    description=f"The target contains an unresolved token '{unexpanded[0]}' instead of an actual address.",
                    remediation_hint="Replace variable with an actual IP address, domain, or URL.",
                    can_auto_remedy=True,
                    remedy_label=f"Set '{default_target}'",
                    remedy_action="set_default_target",
                    remedy_payload=default_target,
                )
            )
            return

        has_scheme = target.startswith("http://") or target.startswith("https://")

        # Scheme rules for tools that ONLY accept Web URL
        if is_web and not has_scheme:
            fixed_target = f"http://{target}"
            report.issues.append(
                PreflightIssue(
                    category="target",
                    severity="error",
                    title=f"Web tool '{tool_name}' requires an HTTP/HTTPS URL",
                    description=f"Target '{target}' is missing the protocol scheme ('http://' or 'https://').",
                    remediation_hint=f"Prepend 'http://' to the target URL: '{fixed_target}'.",
                    can_auto_remedy=True,
                    remedy_label=f"Set '{fixed_target}'",
                    remedy_action="fix_target_scheme",
                    remedy_payload=fixed_target,
                )
            )

        # Scheme rules for Network and Domain tools that do NOT accept URLs (warnings)
        elif is_network_or_domain and has_scheme:
            clean_host = self._extract_clean_hostname(target)
            report.issues.append(
                PreflightIssue(
                    category="target",
                    severity="warning",
                    title=f"Tool '{tool_name}' expects a host or IP, not a URL",
                    description=f"Target '{target}' contains a URL scheme and/or path which may cause probe errors.",
                    remediation_hint=f"Strip URL scheme and path to use bare hostname '{clean_host}'.",
                    can_auto_remedy=True,
                    remedy_label=f"Strip to '{clean_host}'",
                    remedy_action="strip_url_scheme",
                    remedy_payload=clean_host,
                )
            )

    def _check_wordlists(
        self,
        tool_name: str,
        flags: str,
        report: PreflightReport,
    ) -> None:
        """Inspect command flags for wordlist dependencies and ensure required files exist."""
        dest_dir = self.wordlists_dir or paths.get_default_wordlists_dir()
        dest_path = os.path.abspath(dest_dir)

        # 1. Macro Tokens: {wordlist:name} or {wordlist}
        macro_matches = WORDLIST_MACRO_REGEX.findall(flags)
        for named in macro_matches:
            wl_key = named.strip() if named else DEFAULT_WORDLIST_NAME
            if wl_key.endswith(".txt"):
                wl_key = wl_key[:-4]

            candidate_path = os.path.join(dest_dir, f"{wl_key}.txt")
            if not os.path.exists(candidate_path):
                report.issues.append(
                    PreflightIssue(
                        category="wordlist",
                        severity="error",
                        title=f"Wordlist '{wl_key}' is not available on disk",
                        description=f"The required wordlist asset '{wl_key}.txt' is missing from {dest_dir}.",
                        remediation_hint=f"Install bundled starter wordlists into {dest_dir}.",
                        can_auto_remedy=True,
                        remedy_label="Seed Bundled Wordlists",
                        remedy_action="seed_wordlists",
                        remedy_payload=wl_key,
                    )
                )

        # 2. CLI flags: -w <path> or --wordlist <path> or -w @<macro>
        manifest_uses_wordlist = False
        if self.registry:
            tool_data = self.registry.get_tool(tool_name)
            manifest = tool_data.get("manifest") if isinstance(tool_data, dict) else None
            learning = getattr(manifest, "learning", None) if manifest else None
            if learning and getattr(learning, "recipes", None):
                manifest_uses_wordlist = any(
                    "-w" in r.flags
                    or "--wordlist" in r.flags
                    or any("{wordlist:" in f for f in r.flags)
                    for r in learning.recipes
                )

        is_wordlist_tool = manifest_uses_wordlist or "--wordlist" in flags or "-w" in flags
        if is_wordlist_tool:
            flag_matches = WORDLIST_FLAG_REGEX.findall(flags)
            if not flag_matches and manifest_uses_wordlist and not macro_matches:
                report.issues.append(
                    PreflightIssue(
                        category="wordlist",
                        severity="warning",
                        title="No wordlist flag specified for enumeration tool",
                        description=f"{tool_name.capitalize()} typically requires a wordlist flag (-w) to perform discovery.",
                        remediation_hint=f"Add '-w {{{DEFAULT_WORDLIST_NAME}}}' or specify a wordlist path.",
                        can_auto_remedy=False,
                    )
                )

            for raw_path in flag_matches:
                clean_path = raw_path.strip().strip("'\"")
                if clean_path.startswith("-") or ("{" in clean_path and "}" in clean_path):
                    continue

                if clean_path.startswith("@"):
                    # Legacy @macro syntax
                    wl_name = clean_path[1:]
                    if wl_name.endswith(".txt"):
                        wl_name = wl_name[:-4]
                    candidate = paths.get_wordlist_path(wl_name, data_dir=self.wordlists_dir)
                    if not os.path.exists(candidate):
                        report.issues.append(
                            PreflightIssue(
                                category="wordlist",
                                severity="warning",
                                title=f"Wordlist macro '@{wl_name}' is not yet seeded",
                                description=f"The requested wordlist file does not exist at '{candidate}'.",
                                remediation_hint="Extract bundled wordlists to initialize local dictionaries.",
                                can_auto_remedy=True,
                                remedy_label="Extract Wordlists",
                                remedy_action="seed_wordlists",
                                remedy_payload=wl_name,
                            )
                        )
                else:
                    expanded = os.path.abspath(os.path.expanduser(clean_path))
                    if not os.path.isfile(expanded):
                        report.issues.append(
                            PreflightIssue(
                                category="wordlist",
                                severity="error",
                                title=f"Specified wordlist file not found: '{clean_path}'",
                                description=f"Path '{expanded}' does not exist on disk.",
                                remediation_hint="Verify the wordlist path or seed bundled starter dictionaries.",
                                can_auto_remedy=True,
                                remedy_label="Seed Bundled Wordlists",
                                remedy_action="seed_wordlists",
                                remedy_payload=DEFAULT_WORDLIST_NAME,
                            )
                        )

    @staticmethod
    def _extract_clean_hostname(url_or_target: str) -> str:
        """Extract a clean domain or IP address from a URL or socket target."""
        raw = url_or_target.strip()
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or url_or_target
        return host
