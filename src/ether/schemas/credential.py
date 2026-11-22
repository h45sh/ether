"""Credential finding schemas."""

from typing import ClassVar, Optional

from ether.schemas.base import BaseFinding, Relation


class CredentialFound(BaseFinding):
    """A username/password or token discovery. Linked to a host or domain. Produced by hydra, medusa, leak-lookups."""

    schema_type: str = "credential.found"
    pik_fields: ClassVar[list[str]] = ["context", "username"]

    @classmethod
    def create(
        cls,
        context: str,
        username: str,
        password: Optional[str] = None,
        host_ip: Optional[str] = None,
        **kwargs,
    ):
        parent = None
        if host_ip:
            parent = Relation(
                target_type="network.host",
                target_pik={"ip": host_ip},
                via="credential_for_host",
            )

        return cls(
            pik={"context": context, "username": username},
            parent=parent,
            data={
                "context": context,
                "username": username,
                "password": password,
                "host_ip": host_ip,
                **kwargs,
            },
        )

    def to_semantic_text(self) -> str:
        username = self.pik.get("username") or self.data.get("username", "")
        context = self.pik.get("context") or self.data.get("context", "")
        host_ip = self.data.get("host_ip")
        parts = [f"Credential discovered for user '{username}' in context '{context}'"]
        if host_ip:
            parts.append(f"Host: {host_ip}")
        return ". ".join(parts) + "."
