"""DNS and Domain related schemas."""

from typing import ClassVar, List, Optional

from ether.schemas.base import BaseFinding, Relation


class DnsRecord(BaseFinding):
    """A single DNS entry mapping a name to a value. Produced by dig, whois, or passive DNS tools."""

    schema_type: str = "dns.record"
    pik_fields: ClassVar[List[str]] = ["domain", "type", "value"]

    @classmethod
    def create(
        cls,
        domain: str,
        record_type: str,
        value: str,
        resolved_ip: Optional[str] = None,
        soa_serial: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        anchor_hash: Optional[str] = None,
        **kwargs,
    ):
        pik = {
            "domain": domain.lower().strip(),
            "type": record_type.upper(),
            "value": value.strip(),
        }

        associations = []
        if resolved_ip:
            associations.append(
                Relation(
                    target_type="network.host", target_pik={"ip": resolved_ip}, via="resolves_to"
                )
            )

        data = {**pik, "resolved_ip": resolved_ip, **kwargs}
        if soa_serial:
            data["soa_serial"] = soa_serial
            if not anchor_hash:
                anchor_hash = (
                    f"soa:{soa_serial}"
                    if not str(soa_serial).startswith("soa:")
                    else str(soa_serial)
                )
        elif record_type.upper() == "SOA" and not anchor_hash:
            data["soa_serial"] = value.strip()
            anchor_hash = f"soa:{value.strip()}"

        return cls(
            pik=pik,
            associations=associations,
            data=data,
            ttl_seconds=ttl_seconds if ttl_seconds is not None else 3600,
            anchor_hash=anchor_hash,
        )

    def to_semantic_text(self) -> str:
        domain = self.pik.get("domain") or self.data.get("domain", "")
        rec_type = self.pik.get("type") or self.data.get("type", "")
        val = self.pik.get("value") or self.data.get("value", "")
        resolved_ip = self.data.get("resolved_ip")
        parts = [f"DNS Record: {domain} {rec_type} {val}"]
        if resolved_ip:
            parts.append(f"Resolved IP: {resolved_ip}")
        return ". ".join(parts) + "."


class DomainInfo(BaseFinding):
    """Whois registration data for a domain — owner, registrar, dates. Produced by whois."""

    schema_type: str = "domain.info"
    pik_fields: ClassVar[List[str]] = ["domain"]

    @classmethod
    def create(
        cls, domain: str, registrar: Optional[str] = None, organization: Optional[str] = None
    ):
        pik = {"domain": domain.lower().strip()}

        # Link to the broad dns.record namespace for this domain
        associations = [
            Relation(
                target_type="dns.record",
                target_pik={"domain": pik["domain"], "type": "ANY", "value": "ANY"},
                via="whois_data_for",
            )
        ]

        return cls(
            pik=pik,
            associations=associations,
            data={**pik, "registrar": registrar, "organization": organization},
        )


class EntityAlias(BaseFinding):
    """Links two identifiers that represent the same entity (e.g. hostname to IP). Produced by resolvers."""

    schema_type: str = "entity.alias"
    pik_fields: ClassVar[List[str]] = ["source_id", "target_id"]

    @classmethod
    def create(cls, source_id: str, target_id: str, relation_type: str = "alias_of", **kwargs):
        # Links two existing entities (e.g. hostname to IP)
        return cls.from_data(
            {
                "source_id": source_id,
                "target_id": target_id,
                "relation_type": relation_type,
                **kwargs,
            }
        )
