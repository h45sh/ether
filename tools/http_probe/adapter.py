"""Pure-Python HTTP Probe tool adapter with SSRF defense."""

import asyncio
import re
import ssl
import urllib.parse
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.common import sanitize_untrusted_output
from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.common.scope import ScopeValidator
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost, NetworkService, TLSCertificate
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
            host_ip = target.data.get("host_ip") or (
                target.parent.target_pik.get("host_ip") if target.parent else None
            )
            port = target.data.get("port") or (
                target.parent.target_pik.get("port") if target.parent else None
            )
        elif target.schema_type == "network.service":
            host_ip = target.pik.get("host_ip") or target.data.get("host_ip")
            port = int(target.pik.get("port") or target.data.get("port", 80))
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host_ip}:{port}/"
        elif target.schema_type == "network.host":
            host_ip = target.pik.get("ip") or target.data.get("ip")
            url = f"http://{host_ip}/"
        elif target.schema_type in ("dns.record", "domain.info"):
            domain = (
                target.pik.get("domain")
                or target.data.get("domain")
                or target.pik.get("name")
                or target.data.get("name")
            )
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

        # 2. SSRF & Scope Pre-Connect Defense (governed strictly by context.policy)
        policy_str = str(getattr(context, "policy", "safe")).lower()
        is_unrestricted = "unrestricted" in policy_str
        verdict = await ScopeValidator.check_destination(
            url, policy_is_unrestricted=is_unrestricted
        )
        if not verdict.allowed:
            msg = f"Target '{url}' blocked by SSRF policy ({verdict.reason})."
            await context.spool_line(f"[!] SSRF Defense Triggered: {msg}", is_error=True)
            raise PolicyViolationError(msg)

        # 3. Request execution with DNS-pinned PinnedTransport
        from ether.common.transport import PinnedTransport, SSRFPinnedError

        timeout_sec = float(params.get("timeout", 10.0))
        flags_list = self.normalize_flags(params)
        has_insecure_flag = any(tok in ("-k", "--insecure") for tok in flags_list)
        explicit_insecure = has_insecure_flag or (params.get("verify_tls") is False)
        if explicit_insecure and not is_unrestricted:
            msg = "TLS verification bypass (-k/--insecure/verify_tls=False) is forbidden under GatePolicy.SAFE."
            await context.spool_line(f"[!] Policy Violation: {msg}", is_error=True)
            raise PolicyViolationError(msg)

        verify_tls = (
            False
            if (explicit_insecure and is_unrestricted)
            else bool(params.get("verify_tls", True))
        )
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not verify_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        # Define a response hook to re-validate any redirect location against the SSRF policy
        async def _redirect_hook(response: httpx.Response) -> None:
            if response.is_redirect:
                location = response.headers.get("Location")
                if location:
                    redirect_url = urllib.parse.urljoin(str(response.request.url), location)
                    redirect_verdict = await ScopeValidator.check_destination(
                        redirect_url,
                        scope=getattr(context, "scope", None),
                        policy_is_unrestricted=is_unrestricted,
                    )
                    if not redirect_verdict.allowed:
                        msg = f"Redirect target '{redirect_url}' blocked by SSRF policy ({redirect_verdict.reason})."
                        await context.spool_line(
                            f"[!] SSRF Redirect Defense Triggered: {msg}", is_error=True
                        )
                        raise PolicyViolationError(msg)

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

        # 4. Extract TLS certificate fingerprint if HTTPS
        tls_fingerprint: Optional[str] = params.get("tls_cert_sha256") or params.get(
            "tls_fingerprint"
        )
        if not tls_fingerprint and scheme == "https":
            import hashlib
            import socket

            try:
                with socket.create_connection(
                    (hostname, port), timeout=min(timeout_sec, 5.0)
                ) as sock:
                    with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        if cert_der:
                            tls_fingerprint = hashlib.sha256(cert_der).hexdigest()
                            await context.spool_line(
                                f"[+] TLS Certificate SHA-256: {tls_fingerprint}"
                            )
            except Exception as ssl_err:
                await context.spool_line(
                    f"[-] Could not retrieve TLS certificate directly: {ssl_err}"
                )

        client_cm = (
            PinnedTransport.create_client(
                scope=getattr(context, "scope", None),
                timeout=timeout_sec,
                policy_is_unrestricted=is_unrestricted,
            )
            if verify_tls
            else PinnedTransport.create_unverified_client(
                scope=getattr(context, "scope", None),
                timeout=timeout_sec,
                policy_is_unrestricted=is_unrestricted,
            )
        )
        async with client_cm as client:
            try:
                response = await asyncio.wait_for(client.get(url), timeout=timeout_sec)
            except SSRFPinnedError as exc:
                msg = f"Target blocked by SSRF policy: {exc}"
                await context.spool_line(
                    f"[!] SSRF Redirect Defense Triggered: {msg}", is_error=True
                )
                raise PolicyViolationError(msg) from exc
            except PolicyViolationError:
                raise
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
            body_preview = (
                sanitize_untrusted_output(response.text[:2048]) if response.text else None
            )
            if response.history:
                redirect_location = response.history[0].headers.get("location") or str(response.url)
            elif 300 <= status < 400:
                redirect_location = headers.get("location")
            else:
                redirect_location = None

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

            # 5. Extract Favicon hash
            favicon_hash: Optional[str] = params.get("favicon_hash")
            if not favicon_hash:
                import hashlib

                favicon_url = urllib.parse.urljoin(url, "/favicon.ico")
                try:
                    fav_resp = await client.get(favicon_url)
                    if fav_resp.status_code == 200 and fav_resp.content:
                        favicon_hash = hashlib.sha256(fav_resp.content).hexdigest()
                        await context.spool_line(f"[+] Favicon Hash (SHA-256): {favicon_hash}")
                except Exception:
                    pass

            # 6. Emit findings
            if host_ip:
                yield NetworkHost.create(ip=host_ip)

            tls_anchor = f"tls:{tls_fingerprint}" if tls_fingerprint else None
            svc = NetworkService.create(
                host_ip=host_ip or hostname,
                port=port,
                protocol="tcp",
                service_name=scheme,
                banner=server or None,
                tls_cert_sha256=tls_fingerprint,
                anchor_hash=tls_anchor,
            )
            yield svc

            if tls_fingerprint:
                yield TLSCertificate.create(
                    fingerprint=tls_fingerprint,
                    host_ip=host_ip or hostname,
                    port=port,
                    anchor_hash=tls_anchor,
                )

            endpoint_anchor = (
                tls_anchor if tls_anchor else (f"favicon:{favicon_hash}" if favicon_hash else None)
            )
            endpoint = WebEndpoint.create(
                url=url,
                host_ip=host_ip,
                port=port,
                status_code=status,
                title=title,
                server=server,
                favicon_hash=favicon_hash,
                anchor_hash=endpoint_anchor,
                body_preview=body_preview,
                redirect_location=redirect_location,
                tls_verified=verify_tls,
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
