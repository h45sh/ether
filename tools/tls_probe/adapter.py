"""Native zero-fork in-process TLS prober adapter."""

import asyncio
import hashlib
import ssl
import urllib.parse
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.common.scope import ScopeValidator
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import TLSCertificate, TLSCipherSuite


class TlsProbeAdapter(ToolAdapter):
    """Pure-Python asynchronous TLS prober extracting X.509 certificates and negotiated cipher suites."""

    name = "tls_probe"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        """Pure-Python adapter with zero binary dependencies."""
        return True

    @staticmethod
    def _validate_port(raw_port: Any) -> int:
        """Validate and return a TCP port integer in 1..65535."""
        try:
            port = int(str(raw_port).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid TLS probe port: {raw_port!r}") from exc
        if not (1 <= port <= 65535):
            raise ValueError(f"TLS probe port out of range (1..65535): {port}")
        return port

    def _extract_flag_port(self, params: Dict[str, Any]) -> Optional[int]:
        """Extract -p / --port value from params['flags'] if present."""
        tokens = self.normalize_flags(params)
        for idx, tok in enumerate(tokens):
            if tok in ("-p", "--port"):
                if idx + 1 >= len(tokens):
                    raise ValueError(f"Missing port value after '{tok}' flag.")
                return self._validate_port(tokens[idx + 1])
            if tok.startswith("--port="):
                return self._validate_port(tok.split("=", 1)[1])
            if tok.startswith("-p") and len(tok) > 2 and tok[2:].isdigit():
                return self._validate_port(tok[2:])
        return None

    def _resolve_target_host_port(
        self, target: BaseFinding, params: Dict[str, Any], *, strict: bool = True
    ) -> tuple[str, int]:
        """Resolve (host, port) with precedence: explicit flag > URL/host:port > params['port'] > 443."""
        raw_host = self.extract_host(target) or "127.0.0.1"
        url_or_host_port: Optional[int] = None

        if "://" in raw_host:
            parsed = urllib.parse.urlparse(raw_host)
            host = parsed.hostname or raw_host
            if parsed.port is not None:
                url_or_host_port = self._validate_port(parsed.port)
        elif ":" in raw_host and not raw_host.startswith("[") and raw_host.count(":") == 1:
            host_part, port_part = raw_host.rsplit(":", 1)
            host = host_part
            if port_part.isdigit():
                url_or_host_port = self._validate_port(port_part)
        else:
            host = raw_host

        try:
            flag_port = self._extract_flag_port(params)
        except ValueError:
            if strict:
                raise
            flag_port = None
        if flag_port is not None:
            return host, flag_port

        if url_or_host_port is not None:
            return host, url_or_host_port

        target_port = self.extract_port(target)
        if target_port is not None:
            return host, self._validate_port(target_port)

        if params.get("port") is not None:
            return host, self._validate_port(params["port"])

        return host, 443

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """CLI shim if ever invoked via subprocess."""
        host, port = self._resolve_target_host_port(target, params, strict=False)
        return ["tls_probe", f"{host}:{port}"]

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[BaseFinding]:
        """Fuzz resilience shim."""
        return
        yield

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Perform zero-fork TLS handshake against target and yield certificate and cipher findings."""
        host, port = self._resolve_target_host_port(target, params)

        policy_str = str(getattr(context, "policy", "safe")).lower()
        is_unrestricted = "unrestricted" in policy_str
        verdict = await ScopeValidator.check_destination(
            host, policy_is_unrestricted=is_unrestricted
        )
        if not verdict.allowed:
            raise PolicyViolationError(
                f"Target '{host}' blocked by SSRF policy ({verdict.reason})."
            )

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=params.get("timeout", 5.0),
            )
        except Exception as e:
            await context.spool_line(
                f"TLS probe connection failed to {host}:{port}: {e}", is_error=True
            )
            return

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cipher_info = writer.get_extra_info("cipher")

            der_cert = None
            if ssl_obj:
                try:
                    der_cert = ssl_obj.getpeercert(binary_form=True)
                except Exception:
                    pass

            if der_cert:
                sha256_fp = hashlib.sha256(der_cert).hexdigest()
                yield TLSCertificate.create(
                    fingerprint=sha256_fp,
                    host_ip=host,
                    port=port,
                )

            if cipher_info:
                name, proto, bits = cipher_info
                deprecated = proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")
                yield TLSCipherSuite.create(
                    host_ip=host,
                    port=port,
                    cipher_suite=name,
                    protocol_version=proto,
                    deprecated=deprecated,
                    bits=bits,
                )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
