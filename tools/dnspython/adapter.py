"""Pure-Python DNS Probe tool adapter."""

import json
import sys
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.dns import DnsRecord
from ether.schemas.network import NetworkHost


class DnsPythonAdapter(ToolAdapter):
    """Adapter for the dnspython query and zone transfer engine."""

    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        """Dnspython is a bundled Python dependency, always valid if importable."""
        if "dns.resolver" in sys.modules:
            return True
        try:
            import dns.resolver  # noqa: F401

            return True
        except ImportError:
            return False

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Execute DNS resolution natively in-process using dns.asyncresolver."""
        import dns.asyncquery
        import dns.asyncresolver
        import dns.rdatatype
        import dns.resolver
        import dns.reversename
        import dns.zone

        query: Optional[str] = None
        if target.schema_type == "dns.record":
            query = target.pik.get("domain") or target.data.get("domain")
        elif target.schema_type == "network.host":
            query = target.pik.get("ip") or target.data.get("ip")

        if not query:
            query = params.get("target") or params.get("domain") or params.get("ip")

        if not query:
            await context.spool_line(
                f"[-] Target {target.schema_type} missing query field (domain/ip)",
                is_error=True,
            )
            return

        flag_args = self.normalize_flags(params)

        record_types: List[str] = []
        nameserver: Optional[str] = params.get("nameserver")
        timeout: float = float(params.get("timeout", 5.0))

        # Parse flags
        i = 0
        while i < len(flag_args):
            arg = flag_args[i]
            if arg in ("-t", "--type") and i + 1 < len(flag_args):
                record_types.extend([t.strip().upper() for t in flag_args[i + 1].split(",")])
                i += 2
            elif arg in ("-s", "--server") and i + 1 < len(flag_args):
                nameserver = flag_args[i + 1]
                i += 2
            elif arg.startswith("@"):
                nameserver = arg[1:]
                i += 1
            elif arg in ("--timeout",) and i + 1 < len(flag_args):
                try:
                    timeout = float(flag_args[i + 1])
                except ValueError:
                    pass
                i += 2
            else:
                i += 1

        if not record_types:
            if params.get("record_type"):
                record_types = [params["record_type"].upper()]
            elif target.schema_type == "network.host":
                record_types = ["PTR"]
            else:
                record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        if nameserver:
            resolver.nameservers = [nameserver]

        await context.spool_line(
            f"[*] Native DNS resolution initiated for '{query}' (types: {', '.join(record_types)})"
        )

        for rtype in record_types:
            if rtype == "PTR":
                try:
                    rev_name = dns.reversename.from_address(query)
                    await context.spool_line(f"[*] Querying PTR for {rev_name}...")
                    answers = await resolver.resolve(rev_name, "PTR")
                    for rdata in answers:
                        val = str(rdata.target).rstrip(".")
                        ttl_sec = int(answers.ttl) if hasattr(answers, "ttl") else 3600
                        await context.spool_line(f"[+] {query} PTR {val} (TTL={ttl_sec})")
                        yield DnsRecord.create(
                            domain=val,
                            record_type="PTR",
                            value=val,
                            resolved_ip=query,
                            ttl_seconds=ttl_sec,
                        )
                except Exception as e:
                    await context.spool_line(
                        f"[-] PTR query failed for {query}: {type(e).__name__} ({e})"
                    )
            elif rtype == "AXFR":
                ns_servers = [nameserver] if nameserver else []
                if not ns_servers:
                    try:
                        ns_answers = await resolver.resolve(query, "NS")
                        ns_servers = [str(r.target).rstrip(".") for r in ns_answers]
                    except Exception as e:
                        await context.spool_line(
                            f"[-] Failed to discover NS for AXFR: {e}", is_error=True
                        )
                for ns in ns_servers:
                    await context.spool_line(
                        f"[*] Attempting AXFR for {query} against nameserver {ns}..."
                    )
                    try:
                        zone = dns.zone.Zone(query)
                        await dns.asyncquery.inbound_xfr(
                            where=ns, txn_manager=zone, timeout=timeout
                        )
                        await context.spool_line(
                            f"[+] AXFR SUCCESS: Zone transfer allowed on {ns} for {query}!"
                        )
                        for name, node in zone.nodes.items():
                            rname = str(name)
                            full_name = f"{rname}.{query}" if rname != "@" else query
                            for rdataset in node.rdatasets:
                                r_type_str = dns.rdatatype.to_text(rdataset.rdtype)
                                for rdata in rdataset:
                                    val = str(rdata).rstrip(".")
                                    ttl_sec = (
                                        int(rdataset.ttl) if hasattr(rdataset, "ttl") else 3600
                                    )
                                    await context.spool_line(
                                        f"    {full_name} {ttl_sec} IN {r_type_str} {val}"
                                    )
                                    resolved_ip = val if r_type_str in ("A", "AAAA") else None
                                    soa_serial = None
                                    if r_type_str == "SOA":
                                        parts = val.split()
                                        if len(parts) >= 3:
                                            soa_serial = parts[2]
                                    yield DnsRecord.create(
                                        domain=full_name,
                                        record_type=r_type_str,
                                        value=val,
                                        resolved_ip=resolved_ip,
                                        soa_serial=soa_serial,
                                        ttl_seconds=ttl_sec,
                                    )
                                    if resolved_ip:
                                        yield NetworkHost.create(ip=resolved_ip)
                        break
                    except Exception as e:
                        await context.spool_line(
                            f"[-] AXFR failed on {ns}: {type(e).__name__} ({e})"
                        )
            else:
                await context.spool_line(f"[*] Querying {rtype} for {query}...")
                try:
                    answers = await resolver.resolve(query, rtype)
                    ttl_sec = int(answers.ttl) if hasattr(answers, "ttl") else 3600
                    for rdata in answers:
                        val = str(rdata).rstrip(".")
                        soa_serial = None
                        if rtype == "SOA":
                            try:
                                soa_serial = str(rdata.serial)
                            except AttributeError:
                                parts = val.split()
                                if len(parts) >= 3:
                                    soa_serial = parts[2]
                        await context.spool_line(f"[+] {query} {ttl_sec} IN {rtype} {val}")
                        resolved_ip = val if rtype in ("A", "AAAA") else None
                        yield DnsRecord.create(
                            domain=query,
                            record_type=rtype,
                            value=val,
                            resolved_ip=resolved_ip,
                            soa_serial=soa_serial,
                            ttl_seconds=ttl_sec,
                        )
                        if resolved_ip:
                            yield NetworkHost.create(ip=resolved_ip)
                except dns.resolver.NXDOMAIN:
                    await context.spool_line(f"[-] {query} does not exist (NXDOMAIN)")
                    break
                except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    await context.spool_line(f"[*] No {rtype} record found for {query}")
                except Exception as e:
                    await context.spool_line(
                        f"[-] Query {rtype} failed for {query}: {type(e).__name__} ({e})"
                    )

        await context.spool_line(f"[*] Native DNS resolution completed for '{query}'")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Construct the CLI command using Python's module invocation."""
        query: Optional[str] = None
        if target.schema_type == "dns.record":
            query = target.pik.get("domain")
        elif target.schema_type == "network.host":
            query = target.pik.get("ip")

        flag_args = self.normalize_flags(params)

        # If user did not provide target query inside flags, attach resolved query
        args = [sys.executable, "-m", "tools.dnspython.cli"]

        if query:
            args.append(query)
        elif not flag_args:
            raise ValueError(
                f"Target finding {target.schema_type} missing query field (domain/ip), and no flags provided."
            )

        # Enforce json output for reliable programmatic parsing
        if "--json" not in flag_args:
            args.append("--json")

        args.extend(flag_args)
        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        """Parse structured JSON records into DnsRecord findings."""
        cleaned = raw_stdout.strip()
        if not cleaned:
            return

        try:
            records = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback in case non-JSON diagnostic messages were printed before the JSON block
            start_bracket = cleaned.find("[")
            end_bracket = cleaned.rfind("]")
            if start_bracket != -1 and end_bracket != -1 and end_bracket > start_bracket:
                try:
                    records = json.loads(cleaned[start_bracket : end_bracket + 1])
                except json.JSONDecodeError:
                    return
            else:
                return

        if not isinstance(records, list):
            records = [records]

        for item in records:
            if not isinstance(item, dict):
                continue
            # Skip error notices that did not produce a record value
            if "value" not in item or not item.get("value"):
                continue

            domain_name = item.get("name", "").rstrip(".")
            rtype = item.get("type", "A").upper()
            val = str(item["value"]).rstrip(".")
            ttl = int(item.get("ttl", 300))
            soa_serial = item.get("serial")
            if not soa_serial and rtype == "SOA":
                parts = val.split()
                if len(parts) >= 3:
                    soa_serial = parts[2]

            resolved_ip = val if rtype == "A" else None
            yield DnsRecord.create(
                domain=domain_name,
                record_type=rtype,
                value=val,
                resolved_ip=resolved_ip,
                soa_serial=soa_serial,
                ttl_seconds=ttl,
            )
