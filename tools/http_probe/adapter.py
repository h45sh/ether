"""Pure-Python HTTP Probe tool adapter with SSRF defense."""

import re
import urllib.parse
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.common.ssrf import check_ssrf_safety
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost, NetworkService
from ether.schemas.web import WebEndpoint, WebTechnology


class HTTPProbeAdapter(ToolAdapter):
    """Native coroutine adapter for HTTP probing and banner grabbing."""

    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        """HTTP probe is a pure-Python adapter relying on httpx."""
        try:
            import httpx  # noqa: F401

            return True
        except ImportError:
            return False

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Shim for CLI command building if ever invoked via subprocess."""
        return ["http_probe", str(target.pik)]

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        """Shim for parsing raw output (fuzz resilience)."""
        return
        yield  # Make it an async generator

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Execute in-process HTTP probe with pre-connect SSRF defense."""
        import httpx

        # 1. Determine target URL
        url: Optional[str] = None
        host_ip: Optional[str] = None
        port: Optional[int] = None

        if target.schema_type == "web.endpoint":
            url = target.pik.get("url") or target.data.get("url")
            host_ip = (
                target.data.get("host_ip")
                or (target.parent.target_pik.get("host_ip") if target.parent else None)
            )
            port = (
                target.data.get("port")
                or (target.parent.target_pik.get("port") if target.parent else None)
            )
        elif target.schema_type == "network.service":
            host_ip = target.pik.get("host_ip") or target.data.get("host_ip")
            port = int(target.pik.get("port") or target.data.get("port", 80))
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host_ip}:{port}/"
        elif target.schema_type == "network.host":
            host_ip = target.pik.get("ip") or target.data.get("ip")
            url = f"http://{host_ip}/"
        elif target.schema_type == "dns.record":
            domain = target.pik.get("domain") or target.data.get("domain")
            url = f"http://{domain}/"

        if not url:
            url = params.get("url") or params.get("target")

        if not url:
            await context.spool_line(
                f"[-] Target {target.schema_type} missing valid URL/host",
                is_error=True,
            )
            return

        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        # 2. SSRF Pre-Connect Defense
        policy = params.get("policy", "safe")
        if policy == "safe":
            try:
                check_ssrf_safety(url)
            except PolicyViolationError as e:
                await context.spool_line(f"[!] SSRF Defense Triggered: {e}", is_error=True)
                raise

        # 3. Request execution with httpx
        timeout_sec = float(params.get("timeout", 10.0))
        limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
        transport = httpx.AsyncHTTPTransport(retries=1, verify=False)

        await context.spool_line(f"[*] Probing {url} (timeout={timeout_sec}s)...")

        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname or ""
        scheme = parsed_url.scheme
        port = parsed_url.port or (443 if scheme == "https" else 80)

        # Pre-resolve host IP if not already set
        if not host_ip:
            import socket

            try:
                addrs = socket.getaddrinfo(hostname, port)
                if addrs:
                    host_ip = addrs[0][4][0]
            except Exception:
                pass

        async with httpx.AsyncClient(
            transport=transport,
            verify=False,
            timeout=httpx.Timeout(timeout_sec, connect=5.0),
            follow_redirects=True,
            limits=limits,
        ) as client:
            try:
                response = await client.get(url)
            except Exception as exc:
                await context.spool_line(
                    f"[-] HTTP request to {url} failed: {type(exc).__name__} ({exc})",
                    is_error=True,
                )
                return

            status = response.status_code
            headers = dict(response.headers)
            server = headers.get("server", "").strip()
            x_powered = headers.get("x-powered-by", "").strip()

            await context.spool_line(f"[+] HTTP {status} {response.reason_phrase} - {url}")
            for h_name, h_val in headers.items():
                await context.spool_line(f"    {h_name}: {h_val}")

            # Extract <title>
            title: Optional[str] = None
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL
            )
            if title_match:
                title = title_match.group(1).strip()
                await context.spool_line(f"[+] Page Title: {title}")

            # 4. Emit findings
            if host_ip:
                yield NetworkHost.create(ip=host_ip)

            svc = NetworkService.create(
                host_ip=host_ip or hostname,
                port=port,
                protocol="tcp",
                service_name=scheme,
                banner=server or None,
            )
            yield svc

            endpoint = WebEndpoint.create(
                url=url,
                host_ip=host_ip,
                port=port,
                status_code=status,
                title=title,
                server=server,
            )
            yield endpoint

            if server:
                yield WebTechnology.create(
                    url=url,
                    technology_name=server,
                    categories=["web-server"],
                    host_ip=host_ip,
                    port=port,
                )

            if x_powered:
                yield WebTechnology.create(
                    url=url,
                    technology_name=x_powered,
                    categories=["framework"],
                    host_ip=host_ip,
                    port=port,
                )
