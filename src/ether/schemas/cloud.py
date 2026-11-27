"""Canonical schema for discovered cloud infrastructure and assets."""

from typing import Any, ClassVar, Dict, Optional

from ether.schemas.base import BaseFinding


class CloudAsset(BaseFinding):
    """Represents a cloud-hosted resource (S3 bucket, Azure Blob container, GCP bucket, IMDS metadata)."""

    schema_type: str = "cloud.asset"
    pik_fields: ClassVar[list[str]] = ["provider", "resource_id"]

    @classmethod
    def create(
        cls,
        provider: str,
        resource_id: str,
        service: Optional[str] = None,
        public_access: bool = False,
        region: Optional[str] = None,
        url: Optional[str] = None,
        **kwargs: Any,
    ) -> "CloudAsset":
        pik = {
            "provider": str(provider).lower().strip(),
            "resource_id": str(resource_id).strip(),
        }
        data: Dict[str, Any] = {
            **pik,
            "service": service or "storage",
            "public_access": public_access,
            "region": region,
            "url": url,
            **kwargs,
        }
        return cls(
            pik=pik,
            data=data,
        )

    def to_semantic_text(self) -> str:
        provider = self.pik.get("provider") or self.data.get("provider", "")
        resource_id = self.pik.get("resource_id") or self.data.get("resource_id", "")
        service = self.data.get("service") or "cloud asset"
        access = "publicly accessible" if self.data.get("public_access") else "access restricted"
        parts = [f"{provider.upper()} {service} asset '{resource_id}' ({access})"]
        region = self.data.get("region")
        if region:
            parts.append(f"Region: {region}")
        url = self.data.get("url")
        if url:
            parts.append(f"Resource URL: {url}")
        return ". ".join(parts)
