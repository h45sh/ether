"""Web-related finding schemas."""

from typing import Any, ClassVar, Dict, Optional

from ether.schemas.base import BaseFinding, Relation


class WebEndpoint(BaseFinding):
    """A reachable HTTP/S URL with response metadata. Child of network.service. Produced by gobuster, curl."""

    schema_type: str = "web.endpoint"
    pik_fields: ClassVar[list[str]] = ["url"]

    @classmethod
    def create(
        cls,
        url: str,
        host_ip: Optional[str] = None,
        port: Optional[int] = None,
        favicon_hash: Optional[str] = None,
        anchor_hash: Optional[str] = None,
        **kwargs,
    ):
        parent = None
        if host_ip and port:
            parent = Relation(
                target_type="network.service",
                target_pik={
                    "host_ip": host_ip,
                    "port": port,
                    "protocol": "tcp",  # Default for web
                },
                via="hosts_endpoint",
            )
        data = {"url": url, **kwargs}
        if favicon_hash:
            data["favicon_hash"] = favicon_hash
            if not anchor_hash:
                anchor_hash = (
                    f"favicon:{favicon_hash}"
                    if not favicon_hash.startswith("favicon:")
                    else favicon_hash
                )

        return cls(pik={"url": url}, parent=parent, data=data, anchor_hash=anchor_hash)

    def to_semantic_text(self) -> str:
        url = self.pik.get("url") or self.data.get("url", "")
        status = self.data.get("status_code")
        title = self.data.get("title")
        server = self.data.get("server")
        parts = [f"Web Endpoint at {url}"]
        if status:
            parts.append(f"Status HTTP {status}")
        if title:
            parts.append(f"Page Title: '{title}'")
        if server:
            parts.append(f"Server header: {server}")
        return ". ".join(parts) + "."


class WebResource(BaseFinding):
    """A specific asset (JS, CSS, Image) found on a web endpoint. Child of web.endpoint. Produced by burp, crawler."""

    schema_type: str = "web.resource"
    pik_fields: ClassVar[list[str]] = ["url", "resource_path"]

    @classmethod
    def create(cls, url: str, resource_path: str, **kwargs):
        return cls.from_data(
            {"url": url, "resource_path": resource_path, **kwargs},
            parent=Relation(
                target_type="web.endpoint", target_pik={"url": url}, via="hosts_resource"
            ),
        )


class WebVulnerability(BaseFinding):
    """A web-specific flaw (XSS, SQLi) found on an endpoint. Child of web.endpoint. Produced by nikto, zap."""

    schema_type: str = "web.vulnerability"
    pik_fields: ClassVar[list[str]] = ["url", "vuln_type", "parameter"]

    @classmethod
    def create(cls, url: str, vuln_type: str, parameter: Optional[str] = None, **kwargs):
        return cls(
            pik={"url": url, "vuln_type": vuln_type, "parameter": parameter or ""},
            parent=Relation(
                target_type="web.endpoint", target_pik={"url": url}, via="has_web_vuln"
            ),
            data={"url": url, "vuln_type": vuln_type, "parameter": parameter, **kwargs},
        )


class WebTechnology(BaseFinding):
    """A detected web technology, framework, server, or CMS. Child of web.endpoint or network.service. Produced by whatweb, wappalyzer, httpx, nikto."""

    schema_type: str = "web.technology"
    pik_fields: ClassVar[list[str]] = ["url", "technology_name"]

    @classmethod
    def create(
        cls,
        url: str,
        technology_name: str,
        version: Optional[str] = None,
        categories: Optional[list[str]] = None,
        cpe: Optional[str] = None,
        confidence: float = 1.0,
        host_ip: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs,
    ):
        parent = None
        if host_ip and port:
            parent = Relation(
                target_type="network.service",
                target_pik={
                    "host_ip": host_ip,
                    "port": port,
                    "protocol": "tcp",
                },
                via="service_uses_technology",
            )
        else:
            parent = Relation(
                target_type="web.endpoint",
                target_pik={"url": url},
                via="endpoint_uses_technology",
            )

        cls_kwargs = {}
        if "schema_version" in kwargs:
            cls_kwargs["schema_version"] = kwargs.pop("schema_version")
        if "status" in kwargs:
            cls_kwargs["status"] = kwargs.pop("status")

        data = {
            "url": url,
            "technology_name": technology_name,
            "version": version,
            "categories": categories or [],
            "cpe": cpe,
            "confidence": max(0.0, min(1.0, float(confidence))),
            **kwargs,
        }
        if host_ip:
            data["host_ip"] = host_ip
        if port:
            data["port"] = port

        return cls(
            pik={"url": url, "technology_name": technology_name},
            parent=parent,
            data=data,
            **cls_kwargs,
        )

    def to_semantic_text(self) -> str:
        url = self.pik.get("url") or self.data.get("url", "")
        tech = self.pik.get("technology_name") or self.data.get("technology_name", "")
        version = self.data.get("version")
        categories = self.data.get("categories", [])
        cpe = self.data.get("cpe")
        parts = [f"Web Technology '{tech}' identified on {url}"]
        if version:
            parts.append(f"Version: {version}")
        if categories:
            parts.append(f"Categories: {', '.join(categories)}")
        if cpe:
            parts.append(f"CPE: {cpe}")
        return ". ".join(parts) + "."


class WebParameter(BaseFinding):
    """Represents an HTTP parameter discovered via URL crawling, fuzzing, or parameter mining (e.g. Arjun)."""

    schema_type: str = "web.parameter"
    pik_fields: ClassVar[list[str]] = ["endpoint_url", "param_name", "method"]

    @classmethod
    def create(
        cls,
        endpoint_url: str,
        param_name: str,
        method: str = "GET",
        param_type: Optional[str] = None,
        reflection: bool = False,
        sample_value: Optional[str] = None,
        **kwargs: Any,
    ) -> "WebParameter":
        pik = {
            "endpoint_url": endpoint_url,
            "param_name": param_name,
            "method": method.upper().strip(),
        }
        data: Dict[str, Any] = {
            **pik,
            "param_type": param_type or "query",
            "reflection": reflection,
            "sample_value": sample_value,
            **kwargs,
        }
        return cls(
            pik=pik,
            parent=Relation(
                target_type="web.endpoint", target_pik={"url": endpoint_url}, via="has_parameter"
            ),
            data=data,
        )

    def to_semantic_text(self) -> str:
        url = self.pik.get("endpoint_url") or self.data.get("endpoint_url", "")
        param = self.pik.get("param_name") or self.data.get("param_name", "")
        method = self.pik.get("method") or self.data.get("method", "GET")
        reflected = "reflected" if self.data.get("reflection") else "not reflected"
        parts = [f"Parameter '{param}' on {method} {url} ({reflected})"]
        ptype = self.data.get("param_type")
        if ptype:
            parts.append(f"Type: {ptype}")
        sample = self.data.get("sample_value")
        if sample:
            parts.append(f"Sample: {sample}")
        return ". ".join(parts)
