# PROTECTED FILE — See docs/CONTRIBUTING.md before modifying.
# Changes to this file require team agreement.
"""Foundational Pydantic models for Ether findings."""

from datetime import UTC, datetime
from typing import Any, ClassVar, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_core import PydanticUndefined

from ether.common.canonicalize import canonicalize_mapping


class Relation(BaseModel):
    """Represents an edge in the entity graph."""

    target_type: str  # e.g. "network.host"
    target_pik: Dict[str, Any]  # The PIK fields of the target entity
    via: str  # Relationship name, e.g. "has_service"

    @field_validator("target_pik", mode="before")
    @classmethod
    def apply_canonicalization(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return canonicalize_mapping(v)
        return v


class BaseFinding(BaseModel):
    """The base finding structure all schemas must follow."""

    schema_type: str  # e.g. "network.service"
    schema_version: str = "1.0"
    pik_fields: ClassVar[List[str]] = []  # Declarative PIK fields for registry/linter
    pik: Dict[str, Any]  # Primary Identity Key fields
    parent: Optional[Relation] = None
    associations: List[Relation] = Field(default_factory=list)
    data: Dict[str, Any]  # Additional finding data
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: Literal["proposed", "confirmed", "flapping", "stale"] = "confirmed"
    ttl_seconds: int = 3600
    anchor_hash: Optional[str] = None
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_data(
        cls,
        data: Dict[str, Any],
        parent: Optional[Relation] = None,
        associations: Optional[List[Relation]] = None,
        status: Literal["proposed", "confirmed", "flapping", "stale"] = "confirmed",
        ttl_seconds: int = 3600,
        anchor_hash: Optional[str] = None,
    ) -> "BaseFinding":
        """Construct a finding instance deriving its PIK automatically from class pik_fields."""
        pik = {k: data[k] for k in cls.pik_fields if k in data}
        st = ""
        if "schema_type" in cls.model_fields:
            field_def = cls.model_fields["schema_type"].default
            if field_def is not None and field_def is not PydanticUndefined:
                st = str(field_def)
        if not st:
            st = str(data.get("schema_type", ""))

        return cls(
            schema_type=st,
            pik=pik,
            parent=parent,
            associations=associations or [],
            data=data,
            status=status,
            ttl_seconds=ttl_seconds,
            anchor_hash=anchor_hash,
        )

    @field_validator("pik", "data", mode="before")
    @classmethod
    def apply_canonicalization(cls, v: Any) -> Any:
        """Apply declarative normalization filters to PIK and data dictionary fields."""
        if isinstance(v, dict):
            return canonicalize_mapping(v)
        return v

    @model_validator(mode="before")
    @classmethod
    def resolve_anchor_hash(cls, values: Any) -> Any:
        """Derive cryptographic anchor_hash from data dictionary if not explicitly provided."""
        if isinstance(values, dict):
            if not values.get("anchor_hash"):
                inner_data = values.get("data")
                if isinstance(inner_data, dict):
                    for key in (
                        "anchor_hash",
                        "tls_cert_sha256",
                        "ssh_hostkey_fingerprint",
                        "favicon_hash",
                        "soa_serial",
                    ):
                        val = inner_data.get(key)
                        if val:
                            prefix = (
                                "tls"
                                if "tls" in key
                                else (
                                    "ssh"
                                    if "ssh" in key
                                    else (
                                        "favicon"
                                        if "favicon" in key
                                        else ("soa" if "soa" in key else "")
                                    )
                                )
                            )
                            values["anchor_hash"] = (
                                f"{prefix}:{val}"
                                if prefix and not str(val).startswith(f"{prefix}:")
                                else str(val)
                            )
                            break
        return values

    def to_semantic_text(self) -> str:
        """Produce a concise, human-readable semantic text description for vector embedding."""
        pik_desc = ", ".join(f"{k}={v}" for k, v in self.pik.items())
        data_desc = ", ".join(
            f"{k}={v}"
            for k, v in self.data.items()
            if k not in self.pik and v is not None and str(v).strip()
        )
        if data_desc:
            return f"{self.schema_type}: {pik_desc}. Data: {data_desc}."
        return f"{self.schema_type}: {pik_desc}."
