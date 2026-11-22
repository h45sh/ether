"""Network-related finding schemas."""

from typing import ClassVar, Optional

from ether.schemas.base import BaseFinding, Relation


class NetworkHost(BaseFinding):
    """A discovered machine on the network, identified by IP. Root entity for most scans. Produced by nmap."""

    schema_type: str = "network.host"
    pik_fields: ClassVar[list[str]] = ["ip"]

    @classmethod
    def create(cls, ip: str, hostname: Optional[str] = None, os: Optional[str] = None, **kwargs):
        return cls.from_data({"ip": ip, "hostname": hostname, "os": os, **kwargs})

    def to_semantic_text(self) -> str:
        ip = self.pik.get("ip") or self.data.get("ip", "")
        hostname = self.data.get("hostname")
        os_val = self.data.get("os")
        parts = [f"Discovered Host IP: {ip}"]
        if hostname:
            parts.append(f"Hostname: {hostname}")
        if os_val:
            parts.append(f"Operating System: {os_val}")
        return ". ".join(parts) + "."


class NetworkService(BaseFinding):
    """A listening port on a host. Child of network.host. Produced by nmap -sV."""

    schema_type: str = "network.service"
    pik_fields: ClassVar[list[str]] = ["host_ip", "port", "protocol"]

    @classmethod
    def create(
        cls,
        host_ip: str,
        port: int,
        protocol: str = "tcp",
        service_name: Optional[str] = None,
        tls_cert_sha256: Optional[str] = None,
        ssh_hostkey_fingerprint: Optional[str] = None,
        anchor_hash: Optional[str] = None,
        **kwargs,
    ):
        pik = {"host_ip": host_ip, "port": port, "protocol": protocol}
        data = {**pik, "service_name": service_name, **kwargs}
        if tls_cert_sha256:
            data["tls_cert_sha256"] = tls_cert_sha256
            if not anchor_hash:
                anchor_hash = (
                    f"tls:{tls_cert_sha256}"
                    if not tls_cert_sha256.startswith("tls:")
                    else tls_cert_sha256
                )
        if ssh_hostkey_fingerprint:
            data["ssh_hostkey_fingerprint"] = ssh_hostkey_fingerprint
            if not anchor_hash:
                anchor_hash = (
                    f"ssh:{ssh_hostkey_fingerprint}"
                    if not ssh_hostkey_fingerprint.startswith("ssh:")
                    else ssh_hostkey_fingerprint
                )

        return cls(
            pik=pik,
            parent=Relation(
                target_type="network.host", target_pik={"ip": host_ip}, via="has_service"
            ),
            data=data,
            anchor_hash=anchor_hash,
        )

    def to_semantic_text(self) -> str:
        host_ip = self.pik.get("host_ip") or self.data.get("host_ip", "")
        port = self.pik.get("port") or self.data.get("port", "")
        protocol = self.pik.get("protocol") or self.data.get("protocol", "tcp")
        svc = self.data.get("service_name") or "unknown"
        banner = self.data.get("banner")
        tls = self.data.get("tls_cert_sha256")
        parts = [f"{svc} service on {host_ip}:{port}/{protocol}"]
        if banner:
            parts.append(f"Product banner: {banner}")
        if tls:
            parts.append(f"TLS SHA-256: {tls}")
        return ". ".join(parts) + "."


class NetworkNetblock(BaseFinding):
    """An IP range with ownership data — org, ASN, CIDR. Produced by whois against an IP."""

    schema_type: str = "network.netblock"
    pik_fields: ClassVar[list[str]] = ["cidr"]

    @classmethod
    def create(cls, cidr: str, organization: Optional[str] = None, asn: Optional[str] = None):
        pik = {"cidr": cidr.strip()}
        return cls(pik=pik, data={**pik, "organization": organization, "asn": asn})


class TLSCertificate(BaseFinding):
    """A TLS certificate associated with a service. Child of network.service. Produced by sslscan, nmap-scripts."""

    schema_type: str = "tls.certificate"
    pik_fields: ClassVar[list[str]] = ["fingerprint"]

    @classmethod
    def create(
        cls,
        fingerprint: str,
        host_ip: str,
        port: int,
        anchor_hash: Optional[str] = None,
        **kwargs,
    ):
        if not anchor_hash and fingerprint:
            anchor_hash = (
                f"tls:{fingerprint}" if not fingerprint.startswith("tls:") else fingerprint
            )
        return cls(
            pik={"fingerprint": fingerprint},
            parent=Relation(
                target_type="network.service",
                target_pik={"host_ip": host_ip, "port": port, "protocol": "tcp"},
                via="uses_certificate",
            ),
            data={
                "fingerprint": fingerprint,
                "host_ip": host_ip,
                "port": port,
                **kwargs,
            },
            anchor_hash=anchor_hash,
        )

    def to_semantic_text(self) -> str:
        fp = self.pik.get("fingerprint") or self.data.get("fingerprint", "")
        host = self.data.get("host_ip", "")
        port = self.data.get("port", "")
        return f"TLS Certificate (SHA-256: {fp}) on {host}:{port}."
