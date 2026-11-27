"""Canonical schema for discovered database instances and services."""

from typing import Any, ClassVar, Dict, List, Optional

from ether.schemas.base import BaseFinding, Relation


class DatabaseService(BaseFinding):
    """Represents a database service (MySQL, PostgreSQL, Redis, MongoDB, etc.) discovered on a host."""

    schema_type: str = "database.service"
    pik_fields: ClassVar[list[str]] = ["host_ip", "port", "db_type"]

    @classmethod
    def create(
        cls,
        host_ip: str,
        port: int,
        db_type: str,
        version: Optional[str] = None,
        auth_required: bool = True,
        banner: Optional[str] = None,
        ssl_enabled: bool = False,
        databases: Optional[List[str]] = None,
        users: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> "DatabaseService":
        pik = {
            "host_ip": host_ip,
            "port": int(port),
            "db_type": str(db_type).lower().strip(),
        }
        data: Dict[str, Any] = {
            **pik,
            "version": version,
            "auth_required": auth_required,
            "banner": banner,
            "ssl_enabled": ssl_enabled,
            "databases": databases or [],
            "users": users or [],
            **kwargs,
        }
        return cls(
            pik=pik,
            parent=Relation(
                target_type="network.host", target_pik={"ip": host_ip}, via="hosts_database"
            ),
            data=data,
        )

    def to_semantic_text(self) -> str:
        host_ip = self.pik.get("host_ip") or self.data.get("host_ip", "")
        port = self.pik.get("port") or self.data.get("port", "")
        db_type = self.pik.get("db_type") or self.data.get("db_type", "database")
        version = self.data.get("version") or "unknown"
        auth_req = (
            "auth required"
            if self.data.get("auth_required", True)
            else "unauthenticated access allowed"
        )
        parts = [f"{db_type} database on {host_ip}:{port} (version: {version}, {auth_req})"]
        banner = self.data.get("banner")
        if banner:
            parts.append(f"Greeting banner: {banner}")
        dbs = self.data.get("databases")
        if dbs:
            parts.append(f"Disclosed databases: {', '.join(dbs)}")
        return ". ".join(parts)
